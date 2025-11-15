import httpx
import json
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from httpx import HTTPStatusError

from commons.utils.token_manager import TokenManager  # type: ignore
from commons.interfaces import SecretsManagerInterface, DatabaseServiceInterface  # type: ignore


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class GithubAuthHandler:
    """Handles GitHub OAuth authentication flow"""
    
    def __init__(
        self,
        http_client: httpx.Client,
        db_client: DatabaseServiceInterface,
        config: Dict[str, Any]
    ):
        self.http_client = http_client
        self.db_client = db_client
        self.config = config
    
    def get_oauth_url(self) -> Dict[str, Any]:
        """Generate GitHub OAuth authorization URL"""
        github_oauth_url = (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={self.config['CLIENT_ID']}"
            f"&redirect_uri={self.config['REDIRECT_URI']}"
            f"&scope=user:email"
        )
        return {
            "statusCode": 302,
            "headers": {
                "Location": github_oauth_url
            }
        }
    
    def handle_callback(self, code: str) -> Dict[str, Any]:
        """
        Handle GitHub OAuth callback.
        
        Steps:
        1. Exchange authorization code for access token
        2. Fetch user information from GitHub
        3. Save user information in database
        4. Generate JWT token
        5. Return redirect response with JWT cookie
        """
        try:
            # 1. Exchange authorization code for access token
            logger.info("Fetching access token")
            start = time.time()
            token_response = self.http_client.post(
                url="https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.config['CLIENT_ID'],
                    "client_secret": self.config['github_client_secret'],
                    "code": code,
                    "redirect_uri": self.config['REDIRECT_URI'],
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
            user_response = self.http_client.get(
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
            self.db_client.update(
                collection=self.config['USERS_COLLECTION'],
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
            jwt_token = TokenManager(None).get_jwt_token(   # type: ignore
                private_key=self.config['jwt_key'],
                iss="tgrafy",
                algo="HS256",
                exp=token_expiry_minutes
            )
            
            # 5. Return redirect response with JWT cookie
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
        except Exception as err:
            logger.error("Unexpected error in OAuth callback: %s", str(err))
            return {
                "statusCode": 500,
                "body": json.dumps({
                    "login_status": "FAILED",
                    "error": "Internal server error"
                })
            }
