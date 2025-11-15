from functools import lru_cache
from commons.interfaces import SecretsManagerInterface  # type: ignore
from ..models.dto import AppSecrets
from ..config.settings import (
    SECRET_DATABASE_USERNAME_PATH,
    SECRET_DATABASE_PASSWORD_PATH,
    SECRET_GITHUB_OAUTH,
    SECRET_JWT_PRIVATE_KEY_PATH
)


@lru_cache(maxsize=1)
def load_secrets(
    secrets_manager: SecretsManagerInterface
) -> AppSecrets:
    """Load application secrets from the secrets manager."""
    secrets = tuple(
        secrets_manager.get_secrets([  # type: ignore
            SECRET_GITHUB_OAUTH,
            SECRET_DATABASE_USERNAME_PATH,
            SECRET_DATABASE_PASSWORD_PATH,
            SECRET_JWT_PRIVATE_KEY_PATH
        ])
    )
    
    if None in secrets:
        raise RuntimeError("One or more required secrets are missing")
    
    return AppSecrets(
        github_oauth_client_secret=secrets[0],  # type: ignore
        database_username=secrets[1],   # type: ignore
        database_password=secrets[2],   # type: ignore
        jwt_private_key=secrets[3]  # type: ignore
    )
