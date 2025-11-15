import logging
from typing import Dict, Any
from aws_lambda_powertools.utilities.typing import LambdaContext
from commons.utils.dependencies import get_secrets_manager  # type: ignore

from .utils.router import Router
from .utils.bootstrap import load_secrets
from .config.constants import AUTH_ROUTER_PREFIX
from .config.settings import AWS_REGION_NAME
from .handlers.handler_factory import (
    create_github_auth_handler,
    get_handler_context
)


router = Router()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app_secrets = load_secrets(
    secrets_manager=get_secrets_manager(AWS_REGION_NAME)
)

@router.route("GET", f"{AUTH_ROUTER_PREFIX}/oauth/github")
def github_oauth(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Initiate GitHub OAuth flow by redirecting to GitHub authorization"""
    try:
        handler_context = get_handler_context(app_secrets, context)
        handler = create_github_auth_handler(
            http_client=handler_context['http_client'],
            app_secrets=app_secrets,
            db_client=handler_context['db_client'],
        )
        return handler.get_oauth_url()
    except Exception as err:
        logger.error("Error in github_oauth: %s", str(err))
        return {
            "statusCode": 500,
            "body": '{"error": "Internal server error"}'
        }


@router.route("GET", f"{AUTH_ROUTER_PREFIX}/oauth/github/callback")
def github_oauth_callback(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Handle GitHub OAuth callback and authenticate user"""
    try:
        code = event.get("queryStringParameters", {}).get("code", "")
        if not code:
            return {
                "statusCode": 400,
                "body": '{"error": "Missing authorization code"}'
            }
        
        handler_context = get_handler_context(app_secrets, context)
        handler = create_github_auth_handler(
            http_client=handler_context['http_client'],
            app_secrets=app_secrets,
            db_client=handler_context['db_client'],
        )
        return handler.handle_callback(code)
    except Exception as err:
        logger.error("Error in github_oauth_callback: %s", str(err))
        return {
            "statusCode": 500,
            "body": '{"error": "Internal server error"}'
        }


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    return router.handle(event, context)
