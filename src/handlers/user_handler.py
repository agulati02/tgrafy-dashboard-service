import httpx
from typing import Any, Dict

from commons.interfaces import DatabaseServiceInterface  # type: ignore


class UserHandler:
    """Handler for user-related operations"""

    def __init__(
        self,
        http_client: httpx.Client,
        db_client: DatabaseServiceInterface,
        config: Dict[str, Any]
    ):
        self.http_client = http_client
        self.db_client = db_client
        self.config = config

    def get_profile(self, user_id: str) -> Dict[str, Any]:
        """Fetch the authenticated user's profile information"""
        user_details: Dict[str, Any] = self.db_client.query(
            collection=self.config['USERS_COLLECTION'],
            filter={"login": user_id},
        )[0]
        return user_details
