import httpx
import json
import time
import logging
from datetime import datetime, timezone
from httpx import HTTPStatusError
from typing import Dict, Any
from aws_lambda_powertools.utilities.typing import LambdaContext
from commons.utils.dependencies import get_secrets_manager, get_database_service  # type: ignore
from commons.utils.token_manager import TokenManager  # type: ignore
from .utils.router import Router
from .config.constants import AUTH_ROUTER_PREFIX
from .config.settings import (
    CLIENT_ID, 
    REDIRECT_URI, 
    AWS_REGION_NAME,
    SECRET_GITHUB_OAUTH, 
    SECRET_DATABASE_USERNAME_PATH, 
    SECRET_DATABASE_PASSWORD_PATH,
    SECRET_JWT_PRIVATE_KEY_PATH,
    DATABASE_CONNECTION_STRING,
    DATABASE_NAME,
    USERS_COLLECTION
)


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
    secrets_manager = get_secrets_manager(AWS_REGION_NAME)

    # 0. Get secrets
    app_secrets = tuple(
        secrets_manager.get_secrets([  # type: ignore
            SECRET_GITHUB_OAUTH, SECRET_DATABASE_USERNAME_PATH, 
            SECRET_DATABASE_PASSWORD_PATH, SECRET_JWT_PRIVATE_KEY_PATH
        ])
    )

    if None in app_secrets:
        logger.error("One or more required secrets are missing")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "login_status": "FAILED",
                "error": "Internal server error"
            })
        }
    github_client_secret, database_username, database_password, jwt_key = app_secrets
    with httpx.Client() as http_client, \
        get_database_service(
            conn_string=DATABASE_CONNECTION_STRING,
            database_name=DATABASE_NAME,
            username=database_username,
            password=database_password
        ) as db_client:

        # 1. Exchange authorization code for access token
        logger.info("Fetching access token")
        start = time.time()
        token_response = http_client.post(
            url="https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": CLIENT_ID,
                "client_secret": github_client_secret,
                "code": code,
                "redirect_uri": REDIRECT_URI,
            }
        )
        logger.info("Access token call took: %f sec", time.time() - start)
        try:
            token_response.raise_for_status()
        except HTTPStatusError as err:
            logger.error("Error fetching access token: %s", str(err))
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "login_status": "FAILED",
                    "error": str(err)
                })
            }
        
        token_data: Dict[str, Any] = token_response.json()
        access_token = token_data.get("access_token")

        # 2. Fetch user information
        logger.info("Fetching user data")
        start = time.time()
        user_response = http_client.get(
            url="https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        )
        logger.info("User data call took: %f sec", time.time() - start)
        
        try:
            user_response.raise_for_status()
        except HTTPStatusError as err:
            logger.error("Error fetching user data: %s", str(err))
            return {
                "statusCode": 500,
                "body": json.dumps({
                    "login_status": "FAILED",
                    "error": str(err)
                })
            }
            
        user_data: Dict[str, Any] = user_response.json()

        # 3. Save user information in DB
        logger.info("Saving user details to DB")
        start = time.time()
        db_client.update(
            collection=USERS_COLLECTION,
            filter={"login": user_data["login"]},
            diff={
                **user_data,
                "access_token": access_token,
                "login_ts": datetime.now(tz=timezone.utc)
            },
            upsert=True
        )
        logger.info("User save call took %f sec", time.time() - start)

        # 4. Generate JWT token
        logger.info("Generating JWT token")
        token_expiry_minutes = 10
        jwt_token = TokenManager(secrets_manager).get_jwt_token(
            private_key=jwt_key,    # type: ignore
            iss="tgrafy",
            algo="HS256",
            exp=token_expiry_minutes
        )

        return {
            "statusCode": 302,
            "headers": {
                "Location": f"https://tgrafy.agulati.cc/dashboard?login={user_data['login']}",
                "Set-Cookie": (
                    f"tg_access_token={jwt_token}; "
                    f"Domain=.agulati.cc; HttpOnly; "
                    f"SameSite=None; Secure; Path=/; Max-Age={token_expiry_minutes * 60}"
                )
            }
        }

def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    return router.handle(event, context)
