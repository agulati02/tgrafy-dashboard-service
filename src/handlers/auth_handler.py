import httpx
import time
import logging
from datetime import datetime, timezone
from typing import Callable, Dict, Any
from httpx import HTTPStatusError
from aws_lambda_powertools.utilities.typing import LambdaContext

from commons.utils.token_manager import TokenManager  # type: ignore
from commons.interfaces import DatabaseServiceInterface # type: ignore
import jwt  # type: ignore

from ..utils.typing import *


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
        """Handle GitHub OAuth callback"""
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
                    "headers": {
                        'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                        'Access-Control-Allow-Credentials': True,
                        'Content-Type': 'application/json'
                    },
                    "body": '{"login_status": "FAILED", "error": ' + str(err) + '}'
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
                    "body": '{"login_status": "FAILED", "error": ' + str(err) + '}'
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
            logger.info("Generating access token")
            token_expiry_minutes = 10
            jwt_token = TokenManager(None).get_jwt_token(   # type: ignore
                private_key=self.config['jwt_key'],
                iss="tgrafy",
                algo="HS256",
                exp=token_expiry_minutes,
                sub=user_data["login"]
            )

            # 5. Generate refresh token
            logger.info("Generating refresh token")
            refresh_token_expiry_minutes = 60 * 24 * 7  # 7 days
            refresh_jwt_token = TokenManager(None).get_jwt_token(   # type: ignore
                private_key=self.config['jwt_key'],
                iss="tgrafy",
                algo="HS256",
                exp=refresh_token_expiry_minutes,
                sub=user_data["login"],
                type="refresh"
            )
            
            # 6. Return redirect response with JWT cookie
            logger.info("Generating redirect response")
            return {
                "statusCode": 302,
                "headers": {
                    "Location": f"https://tgrafy.agulati.cc/dashboard?login={user_data['login']}",
                },
                "multiValueHeaders": {
                    "Set-Cookie": [
                        f"TgAccessToken={jwt_token}; Domain=.agulati.cc; SameSite=None; HttpOnly; Secure; Path=/; Max-Age={token_expiry_minutes * 60}",
                        f"TgRefreshToken={refresh_jwt_token}; Domain=.agulati.cc; HttpOnly; SameSite=None; Secure; Path=/; Max-Age={refresh_token_expiry_minutes * 60}"
                    ]
                }
            }
        except Exception as err:
            logger.error("Unexpected error in OAuth callback: %s", str(err))
            return {
                "statusCode": 500,
                "headers": {
                    'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                    'Access-Control-Allow-Credentials': True,
                    'Content-Type': 'application/json'
                },
                "body": '{"login_status": "FAILED", "error": "Internal server error"}'
            }
    
    def refresh_jwt(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Refresh JWT token using the provided refresh token"""
        try:
            # Extract refresh token from cookies
            cookies: str = event.get('headers', {}).get('Cookie', '')
            refresh_token = ''
            for cookie in cookies.split(';'):
                if cookie.strip().startswith('TgRefreshToken='):
                    refresh_token = cookie.strip().replace('TgRefreshToken=', '')
                    break
            
            if not refresh_token or refresh_token == '':
                return {
                    "statusCode": 401,
                    "headers": {
                        'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                        'Access-Control-Allow-Credentials': True,
                        'Content-Type': 'application/json'
                    },
                    "body": '{"access_status": "FAILED", "error": "Missing refresh token"}'
                }
            
            # Verify refresh token
            is_valid = TokenManager(None).verify_jwt(  # type: ignore
                token=refresh_token,
                private_key=self.config['jwt_key'],
                algorithms=["HS256"],
                iss="tgrafy"
            )
            
            if not is_valid:
                return {
                    "statusCode": 401,
                    "headers": {
                        'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                        'Access-Control-Allow-Credentials': True,
                        'Content-Type': 'application/json'
                    },
                    "body": '{"access_status": "FAILED", "error": "Invalid refresh token"}'
                }
            
            # Extract user login from token
            payload: Dict[str, Any] = jwt.decode(
                refresh_token,
                self.config['jwt_key'],
                algorithms=["HS256"],
                options={"verify_exp": True}
            )
            user_login = payload.get("sub")
            
            # Generate new JWT token
            token_expiry_minutes = 10
            new_jwt_token = TokenManager(None).get_jwt_token(  # type: ignore
                private_key=self.config['jwt_key'],
                iss="tgrafy",
                algo="HS256",
                exp=token_expiry_minutes,
                sub=user_login
            )
            
            return {
                "statusCode": 200,
                "headers": {
                    "Set-Cookie": (
                        f"TgAccessToken={new_jwt_token}; "
                        f"Domain=.agulati.cc; "
                        f"SameSite=None; Secure; Path=/; Max-Age={token_expiry_minutes * 60}"
                    ),
                    'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                    'Access-Control-Allow-Credentials': True,
                    'Content-Type': 'application/json'
                },
                "body": '{"access_status": "SUCCESS", "message": "JWT token refreshed successfully"}'
            }
        except Exception as err:
            logger.error("Unexpected error in refresh_jwt: %s", str(err))
            return {
                "statusCode": 500,
                "headers": {
                    'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                    'Access-Control-Allow-Credentials': True,
                    'Content-Type': 'application/json'
                },
                "body": '{"access_status": "FAILED", "error": "Internal server error"}'
            }


class AccessHandler:
    """Handled access verification"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def authorise(self):
        """Decorator to verify JWT token from request"""
        def decorator(func: Callable[..., Dict[str, Any]]) -> Callable[..., Dict[str, Any]]:
            def wrapper(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
                """Verify the provided JWT"""
                try:
                    # Extract token from Authorization header
                    logger.info(event)
                    cookies: str = event.get('headers', {}).get('Cookie', '')
                    token = None
                    logger.info(cookies)
                    for cookie in cookies.split(';'):
                        if cookie.strip().startswith('TgAccessToken='):
                            token = cookie.strip().replace('TgRefreshToken=', '')
                            break
                    
                    # Validate token exists
                    if not token:
                        logger.error("Missing access token")
                        return {
                            "statusCode": 401,
                            "headers": {
                                'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                                'Access-Control-Allow-Credentials': True,
                                'Content-Type': 'application/json'
                            },
                            "body": '{"access_status": "UNAUTHORIZED", "error": "Missing or invalid Authorization header"}'
                        }
                    
                    # Verify JWT token
                    is_auth = TokenManager(None).verify_jwt(  # type: ignore
                        token=token,
                        private_key=self.config['jwt_key'],
                        algorithms=["HS256"],
                        iss="tgrafy",
                    )
                    
                    if not is_auth:
                        logger.error("Invalid access token")
                        return {
                            "statusCode": 401,
                            "headers": {
                                'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                                'Access-Control-Allow-Credentials': True,
                                'Content-Type': 'application/json'
                            },
                            "body": '{"access_status": "UNAUTHORIZED","error": "Invalid token"}'
                        }
                    
                    # Token is valid, call the wrapped function
                    return func(event, context)
                except Exception as err:
                    logger.error("Authorization error: %s", str(err))
                    return {
                        "statusCode": 401,
                        "headers": {
                            'Access-Control-Allow-Origin': 'https://tgrafy.agulati.cc',
                            'Access-Control-Allow-Credentials': True,
                            'Content-Type': 'application/json'
                        },
                        "body": '{"access_status": "UNAUTHORIZED", "error": "Authorization verification failed"}'
                    }
            return wrapper
        return decorator
