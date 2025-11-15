"""Handler initialization and dependency injection"""

import httpx
from typing import Dict, Any
from aws_lambda_powertools.utilities.typing import LambdaContext

from commons.utils.dependencies import get_database_service  # type: ignore
from commons.interfaces import DatabaseServiceInterface  # type: ignore
from .auth_handler import GithubAuthHandler
from .user_handler import UserHandler
from ..config.settings import (
    CLIENT_ID,
    REDIRECT_URI,
    DATABASE_CONNECTION_STRING,
    DATABASE_NAME,
    USERS_COLLECTION
)
from ..models.dto import AppSecrets


def create_github_auth_handler(
    http_client: httpx.Client,
    app_secrets: AppSecrets,
    db_client: DatabaseServiceInterface,
) -> GithubAuthHandler:
    """Factory function to create GithubAuthHandler with all dependencies."""    
    
    config: Dict[str, Any] = {
        'CLIENT_ID': CLIENT_ID,
        'REDIRECT_URI': REDIRECT_URI,
        'github_client_secret': app_secrets.github_oauth_client_secret,
        'jwt_key': app_secrets.jwt_private_key,
        'USERS_COLLECTION': USERS_COLLECTION,
    }
    
    return GithubAuthHandler(
        http_client=http_client,
        db_client=db_client,
        config=config
    )


def create_user_handler(
    http_client: httpx.Client,
    app_secrets: AppSecrets,
    db_client: DatabaseServiceInterface,
) -> 'UserHandler':
    """Factory function to create UserHandler with all dependencies."""    
    
    config: Dict[str, Any] = {
        'jwt_key': app_secrets.jwt_private_key,
        'USERS_COLLECTION': USERS_COLLECTION,
    }
    
    return UserHandler(
        http_client=http_client,
        db_client=db_client,
        config=config
    )


def get_handler_context(app_secrets: AppSecrets, context: LambdaContext) -> Dict[str, Any]:
    """Prepare handler context with common dependencies."""
    
    http_client = httpx.Client()
    db_client = get_database_service(
        conn_string=DATABASE_CONNECTION_STRING,
        database_name=DATABASE_NAME,
        username=app_secrets.database_username,
        password=app_secrets.database_password
    )
    
    return {
        'http_client': http_client,
        'db_client': db_client,
    }
