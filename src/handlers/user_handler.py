import httpx
import logging
from typing import Any, Dict, List

from commons.interfaces import DatabaseServiceInterface  # type: ignore

from ..config.settings import CLIENT_ID


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
            select={
                "login_ts": 0,
                "access_token": 0,
                "id": 0,
                "node_id": 0
            }
        )[0]
        if '_id' in user_details:
            user_details['id'] = str(user_details.pop('_id'))
        return user_details
    
    def get_tgrafy_installations(self, user_id: str) -> List[Dict[str, Any]]:
        """Fetch user's TGRAFY installations"""
        user_data = self.db_client.query(
            collection=self.config['USERS_COLLECTION'],
            filter={"login": user_id},
            select={"access_token": 1}
        )[0]
        
        access_token = user_data.get("access_token")
        if not access_token:
            raise ValueError("Access token not found for user")
        
        installations_response = self.http_client.get(
            "https://api.github.com/user/installations",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json"
            }
        )

        installations_response.raise_for_status()
        user_installations = installations_response.json()

        return [
            installation for installation in user_installations.get("installations", []) \
            if 'id' in installation and installation['id'] == CLIENT_ID
        ]
