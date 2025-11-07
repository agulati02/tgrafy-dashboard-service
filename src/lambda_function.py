from typing import Dict, Any
from aws_lambda_powertools.utilities.typing import LambdaContext
from .utils.router import Router
from .config.constants import AUTH_ROUTER_PREFIX
from .config.settings import CLIENT_ID, REDIRECT_URI


router = Router()

@router.route("GET", "/".join([AUTH_ROUTER_PREFIX, "oauth", "github"]))
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

def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    return router.handle(event, context)
