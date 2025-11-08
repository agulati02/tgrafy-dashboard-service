import httpx
import json
import logging
from typing import Dict, Any
from aws_lambda_powertools.utilities.typing import LambdaContext
from commons.utils.dependencies import get_secrets_manager  # type: ignore
from .utils.router import Router
from .config.constants import AUTH_ROUTER_PREFIX
from .config.settings import CLIENT_ID, REDIRECT_URI, AWS_REGION_NAME, SECRET_GITHUB_OAUTH


router = Router()
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

@router.route("GET", f"{AUTH_ROUTER_PREFIX}/oauth/github")
def github_oauth(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    github_oauth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=user:email"
    )
    return {
        "statusCode": 302,
        "headers": {
            "Location": github_oauth_url
        }
    }

@router.route("GET", f"{AUTH_ROUTER_PREFIX}/oauth/github/callback")
def github_oauth_callback(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    code = event.get("queryStringParameters", {}).get("code", "")
    with httpx.Client() as client:
        token_response = client.post(
            url="https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": CLIENT_ID,
                "client_secret": get_secrets_manager(AWS_REGION_NAME).get_secret(SECRET_GITHUB_OAUTH),
                "code": code,
                "redirect_uri": REDIRECT_URI,
            }
        )
        token_data: Dict[str, Any] = token_response.json()

        if "error" in token_data:
            return {
                "statusCode": 400,
                "body": json.dumps(token_data.get("error", {}))
            }
        
        access_token = token_data.get("access_token")
        user_data = client.get(
            url="https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        ).json()

        logger.info(user_data)

        return {
            "statusCode": 200,
            "body": json.dumps(user_data)
        }

def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    return router.handle(event, context)
