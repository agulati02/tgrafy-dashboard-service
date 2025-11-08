import os
from dotenv import load_dotenv


ENV = os.getenv("ENV", "local")
load_dotenv(
    os.path.join(
        os.path.dirname(__file__), "..", "resources", f".env.{ENV.lower()}"
    )
)

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET_PATH = os.getenv(
    "CLIENT_SECRET_PATH",
    os.path.join(os.path.dirname(__file__), "..", "resources", "client-secret.txt")
)

def read_file_content(file_path: str) -> str:
    with open(file_path, "r") as file:
        return file.read().strip()

if ENV.lower() == "local":
    CLIENT_SECRET = read_file_content(CLIENT_SECRET_PATH)

REDIRECT_URI = os.getenv("GITHUB_OAUTH_REDIRECT_URI")
AWS_REGION_NAME = os.getenv("AWS_REGION_NAME", "ap-southeast-2")
SECRET_GITHUB_OAUTH = os.getenv("SECRET_GITHUB_OAUTH", "")
