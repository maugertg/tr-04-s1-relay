import requests
import urllib.parse
from functools import partial

from flask import Blueprint

from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data

enrich_api = Blueprint("enrich", __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


def format_docs(docs):
    """Format CTIM Response"""
    return {"count": len(docs), "docs": docs}


def group_observables(relay_input):
    # Leave only unique pairs.

    result = []
    for obj in relay_input:
        obj["type"] = obj["type"].lower()

        # Get only supported types.
        if obj["type"] in ("sha1"):
            if obj in result:
                continue
            result.append(obj)

    return result


def get_threats(host, api_token, sha1):
    """Query SentinelOne Get threads API for a SHA1 anre return JSON response
    https://usea1-partners.sentinelone.net/apidoc/#!/Threats/get_web_api_v2_0_threats
    """
    headers = {"Authorization": f"ApiToken {api_token}"}
    # params = {"contentHash__contains": sha1}
    params = {"contentHashes": sha1, "limit": 100}
    url = f"https://{host}/web/api/v2.1/threats"
    response = requests.get(url, headers=headers, params=params)

    if response.ok:
        return response.json()


def get_sentinelone_outputs(host, api_token, observables):
    """Iterate over SHA1 observables provided from Threat Reasponse and query SentinelOne"""
    outputs = []
    for obs in observables:
        sha1 = obs["value"]
        response = get_threats(host, api_token, sha1)

        if response:
            response["observable"] = obs
            outputs.append(response)

    return outputs


def extract_target(agentRealtimeInfo, createdDate):
    """Prase agentRealtimeInfo object to build target with
    Hostname, OS, MAC Address, IP, IPv6
    """

    agentComputerName = agentRealtimeInfo.get("agentComputerName")
    agentOsName = agentRealtimeInfo.get("agentOsName")
    networkInterfaces = agentRealtimeInfo.get("networkInterfaces", [])
    agentId = agentRealtimeInfo.get("agentId")

    target = {
        "type": "endpoint",
        "observables": [
            {"value": agentComputerName, "type": "hostname"},
            {"value": agentId, "type": "s1_agent_id"},
        ],
        "observed_time": {"start_time": createdDate},
        "os": agentOsName,
    }

    for interface in networkInterfaces:
        mac_address = interface.get("physical")
        target["observables"].append({"value": mac_address, "type": "mac_address"})
        ips = interface.get("inet")
        ipv6s = interface.get("inet6")
        for ip in ips:
            target["observables"].append({"value": ip, "type": "ip"})
        for ipv6 in ipv6s:
            target["observables"].append({"value": ipv6, "type": "ipv6"})

    return target


def extract_relations(threatInfo, observable):
    """Parse SentinelOne Threat object and build CTIM Observed Relations
    file name of sha1
    file path of sha1
    """
    relations = []

    filePath = threatInfo.get("filePath")
    threatName = threatInfo.get("threatName")

    if filePath:
        relation = {
            "origin": "SentinelOne Threat",
            "relation": "File_Path_Of",
            "source": {"value": filePath, "type": "file_path"},
            "related": observable,
        }

        relations.append(relation)

    if threatName:
        relation = {
            "origin": "SentinelOne Threat",
            "relation": "File_Name_Of",
            "source": {"value": threatName, "type": "file_name"},
            "related": observable,
        }

        relations.append(relation)

    return relations


def extract_sightings(output, observable, host):
    """Parse SentinelOne Threat object and build CTIM Sighting"""
    agentRealtimeInfo = output.get("agentRealtimeInfo", {})
    threatInfo = output.get("threatInfo", {})

    createdAt = threatInfo.get("createdAt")
    mitigationStatus = threatInfo.get("mitigationStatus")
    threat_id = output.get("id")

    resolution_mapping = {
        "marked_as_benign": "allowed",
        "not_mitigated": "detected",
        "mitigated": "contained",
    }

    doc = {
        "confidence": "High",
        "count": 1,
        "description": "SentinelOne Detection",
        "external_ids": [threat_id],
        "id": f"transient:sighting-{threat_id}",
        "internal": True,
        "observables": [observable],
        "observed_time": {"start_time": createdAt},
        "relations": [],
        "schema_version": "1.1.12",
        "sensor": "endpoint",
        # "severity": "string",
        "source": "SentinelOne Threat",
        "source_uri": f"https://{host}/analyze/threats/{threat_id}/overview",
        "targets": [extract_target(agentRealtimeInfo, createdAt)],
        "type": "sighting",
    }

    if mitigationStatus:
        doc["resolution"] = resolution_mapping[mitigationStatus]

    doc["relations"].extend(extract_relations(threatInfo, observable))

    return doc


def extract_indicators(output_indicators):
    docs = []

    for indicator in output_indicators:
        category = indicator.get("category")
        description = indicator.get("description")
        ids = indicator.get("ids")

        doc = {
            "confidence": "High",
            "external_ids": [],
            "id": f"transient:indicator-{sorted(ids)}",
            "producer": "SentinelOne",
            "schema_version": "1.1.12",
            "short_description": description,
            "title": description,
            "source": "SentinelOne",
            "tags": [category],
            "type": "indicator",
            "valid_time": {},
        }

        for indicator_id in ids:
            doc["external_ids"].append(str(indicator_id))

        docs.append(doc)

    return docs


def extract_relationships(output):
    docs = []

    threat_id = output.get("id")
    indicators = output.get("indicators")

    for indicator in indicators:
        ids = indicator.get("ids")

        doc = {
            "id": f"transient:relationship-{threat_id}-{sorted(ids)}",
            "type": "relationship",
            "schema_version": "1.1.12",
            "relationship_type": "sighting-of",
            "source": "SentinelOne",
            "source_ref": f"transient:sighting-{threat_id}",
            "target_ref": f"transient:indicator-{sorted(ids)}",
        }

        docs.append(doc)

    return docs


@enrich_api.route("/deliberate/observables", methods=["POST"])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route("/observe/observables", methods=["POST"])
def observe_observables():
    jwt = get_jwt()
    host = jwt["hostname"]
    api_token = jwt["ApiToken"]
    observables = group_observables(get_observables())

    if not observables:
        return jsonify_data({})

    sentinelone_outputs = get_sentinelone_outputs(host, api_token, observables)

    if not sentinelone_outputs:
        return jsonify_data({})

    indicators = []
    sightings = []
    relationships = []

    for output in sentinelone_outputs:
        data = output.get("data", [])
        observable = output.get("observable")
        for entry in data:
            output_indicators = entry.get("indicators")
            sightings.append(extract_sightings(entry, observable, host))
            if output_indicators:
                indicators.extend(extract_indicators(output_indicators))
                relationships.extend(extract_relationships(entry))

    relay_output = {}

    if sightings:
        relay_output["sightings"] = format_docs(sightings)
    if indicators:
        relay_output["indicators"] = format_docs(indicators)
    if relationships:
        relay_output["relationships"] = format_docs(relationships)

    return jsonify_data(relay_output)


@enrich_api.route("/refer/observables", methods=["POST"])
def refer_observables():
    jwt = get_jwt()
    host = jwt["hostname"]
    observables = get_observables()

    relay_output = []

    observable_to_dv_query_mapping = {
        "md5": 'FileMD5 = "{0}"',
        "sha1": 'FileSHA1 = "{0}"',
        "sha256": 'FileSHA256 = "{0}"',
        "ip": 'DstIP = "{0}" OR SrcIP = "{0}"',
        "ipv6": 'DstIP = "{0}" OR SrcIP = "{0}"',
        "url": 'networkUrl = "{0}"',
        "hostname": 'agentName = "{0}"',
    }

    for obs in observables:

        refer_object = {
            "id": "ref-sentinelone-search-{0}-{1}",
            "title": "Open in Deep Visibility",
            "description": "Open in Deep Visibility",
            "categories": ["SentinelOne", "Deep Visibility", "Search"],
            "url": None,
        }

        if obs["type"] in observable_to_dv_query_mapping:
            refer_object["id"] = refer_object["id"].format(
                obs["type"], urllib.parse.quote(obs["value"])
            )
            queryString = observable_to_dv_query_mapping[obs["type"]].format(
                obs["value"]
            )
            url_encoded_queryString = urllib.parse.quote(queryString)
            url = f"https://{host}/dv?queryString={url_encoded_queryString}&timeFrame=Last30Days"
            refer_object["url"] = url
            relay_output.append(refer_object)

    return jsonify_data(relay_output)
