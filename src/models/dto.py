from pydantic import BaseModel


class AppSecrets(BaseModel):
    database_username: str
    database_password: str
    github_oauth_client_secret: str
    jwt_private_key: str
