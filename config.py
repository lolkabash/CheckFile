import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Flask configuration
SECRET_KEY = os.environ.get(
    "SECRET_KEY", "your-secret-key-here"
)  # Should be set as environment variable in production
DEBUG = (
    os.environ.get("DEBUG", "False").lower() == "true"
)  # Should be set as environment variable in production

# Upload configuration
UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
)
MAX_CONTENT_LENGTH = int(
    os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
)  # 16MB max file size

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.environ.get(
    "VIRUSTOTAL_API_KEY", ""
)  # Should be set as environment variable in production
# VirusTotal API configuration
ALLOWED_EXTENSIONS = os.environ.get(
    "ALLOWED_EXTENSIONS", ""
)  # Should be set as environment variable in production
