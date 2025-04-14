import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Flask configuration
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())
DEBUG = False  # Set to False for production

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
        "js",
    }  # Default allowed extensions

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
