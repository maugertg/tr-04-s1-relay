import requests
import datetime
from flask import Blueprint

from api.utils import get_jwt, jsonify_data, jsonify

health_api = Blueprint("health", __name__)


def get_api_token_details(host, api_token):
    """Query SentinelOne API Token Details API and return JSON response containing date the API key expires
    https://usea1-partners.sentinelone.net/api-doc/api-details?category=users&api=api-token-details
    """
    url = f"https://{host}/web/api/v2.1/users/api-token-details"
    headers = {"Authorization": f"ApiToken {api_token}"}
    data = {"data": {"apiToken": f"{api_token}"}}
    response = requests.post(url, headers=headers, json=data)

    if response.ok:
        return response.json()


def str_to_datetime_ojb(date_string):
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    return datetime.datetime.strptime(date_string, fmt).replace(
        tzinfo=datetime.timezone.utc
    )


@health_api.route("/health", methods=["POST"])
def health():
    jwt = get_jwt()
    host = jwt["hostname"]
    api_token = jwt["ApiToken"]

    api_token_details = get_api_token_details(host, api_token)
    expires_at = api_token_details.get("data", {}).get("expiresAt")
    expires_at_obj = str_to_datetime_ojb(expires_at)

    now = datetime.datetime.now(datetime.timezone.utc)
    until_expiration = expires_at_obj - now

    response = {}

    if until_expiration.days <= 30:
        response["errors"] = [
            {
                "code": "sentine-one-api-token-expires-within-30-days",
                "message": f"API Token, {api_token[:5]}...{api_token[-5:]}, will expire in {until_expiration.days} days!",
                "type": "warning",
            }
        ]
    else:
        response["data"] = {"status": "ok"}

    return jsonify(response)
