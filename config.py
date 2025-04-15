import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Flask configuration
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())
DEBUG = (
    os.environ.get("DEBUG", "False").lower() == "true"
)  # Set to False for production

# Upload configuration
UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
)
MAX_CONTENT_LENGTH = int(
    os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
)  # 16MB max file size

# Get allowed extensions from environment or use the default list
# Format in .env file should be: ALLOWED_EXTENSIONS=txt,pdf,png,jpg,jpeg,gif,doc,docx,xls,xlsx,exe
# If not set, only allow the default types (txt,pdf,png,jpg,jpeg,gif,doc,docx,xls,xlsx,exe)
ALLOWED_EXTENSIONS_STR = os.environ.get("ALLOWED_EXTENSIONS", "")
if ALLOWED_EXTENSIONS_STR:
    ALLOWED_EXTENSIONS = set(ALLOWED_EXTENSIONS_STR.split(","))
else:
    ALLOWED_EXTENSIONS = {
        "txt",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "exe",
    }  # Default allowed extensions

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

VT_UPLOAD_URL = str(
    os.environ.get("VT_UPLOAD_URL", "https://www.virustotal.com/api/v3/files")
)
VT_FILE_CHECK_URL = str(
    os.environ.get("VT_FILE_CHECK_URL", "https://www.virustotal.com/api/v3/files/")
)
VT_ANALYSIS_URL = str(
    os.environ.get("VT_ANALYSIS_URL", "https://www.virustotal.com/api/v3/analyses/")
)

# CSRF Time Limit in seconds (1 hour)
WTF_CSRF_TIME_LIMIT = int(
    os.environ.get("WTF_CSRF_TIME_LIMIT", 3600)
)  # in seconds (1 hour)

# Polling Constants
POLLING_INTERVAL = int(os.environ.get("POLLING_INTERVAL", 5))
POLLING_RETRIES = int(os.environ.get("POLLING_RETRIES", 20))
