import os
import hashlib
import requests
import base64
import time
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

# =============================================================================
# CONFIGURATION: All hard-coded variables are imported from config.py file.
# =============================================================================

import config

# =============================================================================
# FLASK APPLICATION SETUP
# =============================================================================
app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    DEBUG=config.DEBUG,
    UPLOAD_FOLDER=config.UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=config.MAX_CONTENT_LENGTH,
    SESSION_TYPE="filesystem",
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    ALLOWED_EXTENSIONS=config.ALLOWED_EXTENSIONS,
    VIRUSTOTAL_API_KEY=config.VIRUSTOTAL_API_KEY,
    VT_UPLOAD_URL=config.VT_UPLOAD_URL,
    VT_FILE_CHECK_URL=config.VT_FILE_CHECK_URL,
    VT_ANALYSIS_URL=config.VT_ANALYSIS_URL,
    WTF_CSRF_TIME_LIMIT=config.WTF_CSRF_TIME_LIMIT,
    POLLING_INTERVAL=config.POLLING_INTERVAL,
    POLLING_RETRIES=config.POLLING_RETRIES,
)

# Initialize CSRF protection for security
csrf = CSRFProtect(app)

# Ensure the upload folder exists. (Not strictly necessary if file processing is in-memory.)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def allowed_file(filename):
    """
    Check if the filename's extension is among the allowed types.

    :param filename: Name of the file to check.
    :return: True if the file extension is allowed, False otherwise.
    """
    allowed = app.config["ALLOWED_EXTENSIONS"]
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def calculate_file_hash(filepath):
    """
    Calculate the SHA-256 hash of the provided file bytes.

    :param file_bytes: Byte content of the file.
    :return: Hexadecimal digest string representing the hash.
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_file_hash_with_virustotal(file_hash):
    """
    Check if VirusTotal has already scanned a file with the given hash.

    :param file_hash: SHA-256 hash string of the file.
    :return: JSON response from VirusTotal if found, None if not or on error.
    """
    headers = {"x-apikey": app.config["VIRUSTOTAL_API_KEY"]}
    url = f"{app.config["VT_FILE_CHECK_URL"]}{file_hash}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            # File not found, so proceed with file upload.
            return None
        else:
            flash(f"Error checking file hash: {response.status_code}", "warning")
    except Exception as e:
        flash(f"Error connecting to VirusTotal API: {str(e)}", "danger")
    return None


def upload_file_to_virustotal(encoded_file_content, filename):
    """
    Upload a base64-encoded file to VirusTotal and poll for analysis results.

    The function performs two steps:
      1. Upload the file.
      2. Poll for the analysis results by checking the analysis endpoint.

    :param encoded_file_content: Base64 encoded file content.
    :param filename: Original secure filename.
    :return: Dictionary with scan results or error information.
    """
    headers = {"x-apikey": app.config["VIRUSTOTAL_API_KEY"]}
    upload_url = app.config["VT_UPLOAD_URL"]
    try:
        # Upload the file to VirusTotal.
        files = {"file": (filename, encoded_file_content)}
        response = requests.post(upload_url, headers=headers, files=files)
        if response.status_code != 200:
            return {"error": True, "message": f"Upload error: {response.status_code}"}

        # Retrieve the analysis ID from the response.
        analysis_id = response.json().get("data", {}).get("id")
        if not analysis_id:
            return {"error": True, "message": "Failed to retrieve analysis ID."}

        analysis_url = f"{app.config["VT_ANALYSIS_URL"]}{analysis_id}"
        # Poll for analysis results.
        for _ in range(app.config["POLLING_RETRIES"]):
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                status = (
                    analysis_response.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("status")
                )
                if status == "completed":
                    return analysis_response.json()
            time.sleep(app.config["POLLING_INTERVAL"])

        return {"error": True, "message": "Analysis timed out. Please try again later."}
    except Exception as e:
        return {"error": True, "message": f"Error uploading file: {str(e)}"}


# =============================================================================
# ROUTES
# =============================================================================


@app.route("/", methods=["GET"])
def index():
    """
    Render the main index page with information on allowed file types.
    """
    return render_template(
        "index.html", allowed_extensions=app.config["ALLOWED_EXTENSIONS"]
    )


@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Handle file upload requests:
      - Validate the file.
      - Process the file in memory (calculating hash and encoding).
      - Check VirusTotal for prior scans.
      - If not scanned, upload the file to VirusTotal and poll for analysis.
      - Store results in session and redirect to results page.
    """
    # Retrieve the file from the incoming request.
    file = request.files.get("file")
    if not file:
        flash("No file part", "danger")
        return redirect(url_for("index"))

    if file.filename == "":
        flash("No file selected", "danger")
        return redirect(url_for("index"))

    if allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)
        # Read file content into uploads folder for processing.
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Compute the SHA-256 hash of the file content.
        file_hash = calculate_file_hash(filepath)
        flash(f"File hash: {file_hash[:8]}...{file_hash[-8:]}", "info")

        # Check if the file has already been scanned using its hash.
        scan_results = check_file_hash_with_virustotal(file_hash)
        if scan_results:
            flash("File already scanned. Retrieving results.", "success")
            session.update(
                scan_results=scan_results, filename=filename, file_hash=file_hash
            )
            return redirect(url_for("show_results"))

        # Encode the file content (base64) for secure transmission.
        with open(filepath, "rb") as f:
            encoded_file_content = base64.b64encode(f.read()).decode()

        scan_results = upload_file_to_virustotal(encoded_file_content, filename)
        os.remove(filepath)

        if scan_results.get("error"):
            flash(scan_results["message"], "danger")
            return redirect(url_for("index"))

        # Store scan details in session and notify the user.
        session.update(
            scan_results=scan_results, filename=filename, file_hash=file_hash
        )
        flash("File uploaded and scanned successfully.", "success")
        return redirect(url_for("show_results"))
    else:
        flash(
            f"File type not allowed. Allowed types: {', '.join(app.config['ALLOWED_EXTENSIONS'])}",
            "danger",
        )
        return redirect(url_for("index"))


@app.route("/results")
def show_results():
    """
    Render the results page using the scan results stored in session.
    If no results exist in session, prompt the user to upload a file.
    """
    if "scan_results" not in session:
        flash("No scan results found. Please upload a file first.", "warning")
        return redirect(url_for("index"))

    return render_template(
        "results.html",
        results=session.get("scan_results"),
        filename=session.get("filename", "Unknown file"),
        file_hash=session.get("file_hash", "Unknown hash"),
    )


# =============================================================================
# ERROR HANDLERS
# =============================================================================


@app.errorhandler(400)
def handle_csrf_error(e):
    """
    Handle CSRF errors by flashing a message and redirecting to the index page.
    """
    flash("The form has expired. Please try again.", "danger")
    return redirect(url_for("index"))


@app.errorhandler(413)
def request_entity_too_large(error):
    """
    Handle errors where the uploaded file is too large.
    Displays the max allowed file size to the user.
    """
    max_size = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    flash(f"File too large. Max size is {max_size}MB.", "danger")
    return redirect(url_for("index"))


@app.errorhandler(404)
def page_not_found(error):
    """
    Render a custom 404 error page.
    """
    return render_template("error.html", error="Page not found (404)"), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """
    Handle errors when an HTTP method is not allowed for a route.
    """
    flash("The method is not allowed for the requested URL.", "danger")
    return redirect(url_for("index"))


@app.errorhandler(500)
def internal_server_error(error):
    """
    Render a custom 500 error page for internal server errors.
    """
    return render_template("error.html", error="Internal server error (500)"), 500


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Run the Flask app. (Set debug to False in production.)
    app.run(host="0.0.0.0", port=5000, debug=app.config["DEBUG"])
