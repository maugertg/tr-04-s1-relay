import sys
import json
import requests

def get_agent(host, api_token, createdDate, agentId):
    headers = {"Authorization": f"ApiToken {api_token}"}
    url = f'https://{host}/web/api/v2.0/agents?ids={agentId}'
    response = requests.get(url, headers=headers)
    response_json = response.json()

    print(response_json['data'])
    data = response_json.get('data', {})[0]
    print(data)
    computerName = data.get('computerName')
    osName = data.get('osName')
    networkInterfaces = data.get('networkInterfaces', [])

    target = {
        "type": "endpoint",
        "observables": [{"value": computerName, "type": "hostname"}],
        "observed_time": {
            "start_time": createdDate
        },
        "os": osName
    }


    for interface in networkInterfaces:
        mac_address = interface.get('physical')
        ips = interface.get('inet')
        ipv6s = interface.get('inet6')
        target['observables'].append({"value": mac_address, "type": "mac_address"})
        for ip in ips:
            target['observables'].append({"value": ip, "type": "ip"})
        for ipv6 in ipv6s:
            target['observables'].append({"value": ipv6, "type": "ipv6"})            

    return target

def main():
    api_token = "3ObUtGlJcst5quR9cnxmmp68eJI7fL5AsPF8qH2IGrYZoKcfhGo4V3Yo897BYHCbRtZXzsRuan7vy3Ui"
    host = "usea1-partners.sentinelone.net"
    agentId = "861499444215302371"
    createdDate = "2020-05-22T21:41:14.521000"

    response = get_agent(host, api_token, createdDate, agentId)

    print(response)

if __name__ == "__main__":
    main()


agent_json = """{
    "data": [
        {
            "accountId": "433241117337583618",
            "accountName": "SentinelOne",
            "activeDirectory": {
                "computerDistinguishedName": null,
                "computerMemberOf": [],
                "lastUserDistinguishedName": null,
                "lastUserMemberOf": []
            },
            "activeThreats": 0,
            "agentVersion": "4.0.3.53",
            "allowRemoteShell": true,
            "appsVulnerabilityStatus": "up_to_date",
            "computerName": "winlab02",
            "consoleMigrationStatus": "N/A",
            "coreCount": 2,
            "cpuCount": 2,
            "cpuId": "Intel(R) Core(TM) i7-8569U CPU @ 2.80GHz",
            "createdAt": "2020-04-03T15:25:36.692763Z",
            "domain": "WORKGROUP",
            "encryptedApplications": false,
            "externalId": "",
            "externalIp": "24.13.19.41",
            "groupId": "861489039287928910",
            "groupIp": "24.13.19.x",
            "groupName": "Default Group",
            "id": "861499444215302371",
            "inRemoteShellSession": false,
            "infected": false,
            "installerType": ".exe",
            "isActive": false,
            "isDecommissioned": true,
            "isPendingUninstall": false,
            "isUninstalled": false,
            "isUpToDate": true,
            "lastActiveDate": "2020-04-14T20:35:59.450137Z",
            "lastLoggedInUserName": "",
            "licenseKey": "",
            "locationType": "fallback",
            "locations": [
                {
                    "id": "629380164464502476",
                    "name": "Fallback",
                    "scope": "global"
                }
            ],
            "machineType": "server",
            "mitigationMode": "protect",
            "mitigationModeSuspicious": "protect",
            "modelName": "VMware, Inc. - VMware7,1",
            "networkInterfaces": [
                {
                    "id": "869627013557087927",
                    "inet": [
                        "192.168.102.128"
                    ],
                    "inet6": [
                        "fe80::4cc4:d37e:e5a5:7195"
                    ],
                    "name": "Ethernet0",
                    "physical": "00:0c:29:cf:9d:6c"
                }
            ],
            "networkStatus": "connected",
            "osArch": "64 bit",
            "osName": "Windows Server 2019 Datacenter Evaluation",
            "osRevision": "17763",
            "osStartTime": "2020-04-14T20:32:59Z",
            "osType": "windows",
            "osUsername": null,
            "rangerStatus": "NotApplicable",
            "rangerVersion": null,
            "registeredAt": "2020-04-03T15:25:36.689463Z",
            "scanAbortedAt": "2020-04-08T22:02:01.378586Z",
            "scanFinishedAt": null,
            "scanStartedAt": "2020-04-03T15:26:45.715859Z",
            "scanStatus": "aborted",
            "siteId": "861489039271151693",
            "siteName": "Cisco",
            "totalMemory": 4094,
            "updatedAt": "2020-05-22T18:57:07.711321Z",
            "userActionsNeeded": [],
            "uuid": "352e1fa194924350855da3eed767845b"
        }
    ],
    "pagination": {
        "nextCursor": null,
        "totalItems": 1
    }
}"""