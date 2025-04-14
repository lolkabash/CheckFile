from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
import os
import hashlib
import requests
import time
import logging  # Make sure this is imported
from datetime import datetime, timedelta  # Import datetime and timedelta
from werkzeug.utils import secure_filename
import config

# Configure logging first, before creating the Flask app
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)

# Create logger for this module
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["UPLOAD_FOLDER"] = config.UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH  # 16MB max file size
app.config["SESSION_TYPE"] = "filesystem"  # Use filesystem session
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
# Create upload folder if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS
    )


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    # Check if a file was submitted
    if "file" not in request.files:
        flash("No file part", "danger")
        return redirect(request.url)

    file = request.files["file"]

    # If the user does not select a file, browser submits an empty file without a filename
    if file.filename == "":
        flash("No selected file", "danger")
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Calculate file hash (SHA-256)
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # Log file upload
        logger.info(f"File uploaded: {filename}, Hash: {file_hash}")

        # Scan with VirusTotal API
        scan_results = scan_file_with_virustotal(filepath, file_hash)

        # Log the scan results (without sensitive details)
        if scan_results:
            if "error" in scan_results and scan_results["error"]:
                logger.error(
                    f"Scan error: {scan_results.get('message', 'Unknown error')}"
                )
            else:
                logger.info(f"Scan completed for file: {filename}")

        # Store results in session to display on results page
        session["scan_results"] = scan_results
        session["filename"] = filename
        session["file_hash"] = file_hash

        # Log session data to confirm it's been set
        logger.debug(
            f"Session data set: filename={filename}, scan_results present={scan_results is not None}"
        )

        # Clean up - remove the file after scanning
        os.remove(filepath)
        logger.debug(f"Removed uploaded file: {filepath}")

        return redirect(url_for("show_results"))
    else:
        flash(
            f'File type not allowed. Allowed types: {", ".join(config.ALLOWED_EXTENSIONS)}',
            "danger",
        )
        return redirect(request.url)


def scan_file_with_virustotal(filepath, file_hash):
    api_key = config.VIRUSTOTAL_API_KEY

    if not api_key:
        logger.error("No VirusTotal API key found!")
        return {
            "error": True,
            "message": "VirusTotal API key is missing. Please set the VIRUSTOTAL_API_KEY environment variable.",
        }

    headers = {"x-apikey": api_key}

    # First check if the file has been scanned before
    check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        logger.debug(f"Checking if file has been scanned before: {file_hash}")
        response = requests.get(check_url, headers=headers)

        # Log the response status code for debugging
        logger.debug(f"Check response status: {response.status_code}")

        if response.status_code == 200:
            # File was scanned before, return the results
            logger.debug("File was previously scanned, retrieving existing results")

            # Add a small delay to simulate scanning and ensure UI updates properly
            time.sleep(2)

            # For previously scanned files, we need to ensure the data structure is consistent
            # In case the structure is different, we need to normalize it
            result_data = response.json()

            # Check if the result has the expected structure
            if "data" in result_data and "attributes" in result_data["data"]:
                attributes = result_data["data"]["attributes"]

                # Check if we have 'last_analysis_results' instead of 'results'
                if (
                    "last_analysis_results" in attributes
                    and "results" not in attributes
                ):
                    # Copy last_analysis_results to results for template consistency
                    attributes["results"] = attributes["last_analysis_results"]

                # Check if we have 'last_analysis_stats' instead of 'stats'
                if "last_analysis_stats" in attributes and "stats" not in attributes:
                    # Copy last_analysis_stats to stats for template consistency
                    attributes["stats"] = attributes["last_analysis_stats"]

                logger.debug("Normalized results structure for template consistency")

            return result_data
        elif response.status_code == 401:
            logger.error("API key is invalid or missing")
            return {
                "error": True,
                "message": "API authentication error. Please check your VirusTotal API key.",
            }
        elif response.status_code == 404:
            logger.debug("File not found in VirusTotal database, will upload")
            # Continue with upload since file wasn't found
            pass
        else:
            logger.warning(
                f"Unexpected status code from VirusTotal API: {response.status_code}"
            )
    except Exception as e:
        logger.error(f"Error checking file hash: {str(e)}")
        return {
            "error": True,
            "message": f"Error connecting to VirusTotal API: {str(e)}",
        }

    # If file wasn't scanned before, upload it and scan
    upload_url = "https://www.virustotal.com/api/v3/files"

    try:
        logger.debug(f"Uploading file for scanning: {os.path.basename(filepath)}")
        with open(filepath, "rb") as file:
            files = {"file": (os.path.basename(filepath), file)}
            upload_response = requests.post(upload_url, headers=headers, files=files)

        # Log the response status code for debugging
        logger.debug(f"Upload response status: {upload_response.status_code}")

        if upload_response.status_code != 200:
            logger.error(f"Error uploading file: {upload_response.status_code}")
            return {
                "error": True,
                "message": f"Error uploading file: {upload_response.status_code}",
            }

        # Get the analysis ID from the upload response
        upload_json = upload_response.json()

        if "data" not in upload_json:
            logger.error("Unexpected response format from upload")
            return {
                "error": True,
                "message": "Unexpected response format from VirusTotal API during upload",
            }

        analysis_id = upload_json.get("data", {}).get("id")

        if not analysis_id:
            logger.error("Could not get analysis ID from response")
            return {
                "error": True,
                "message": "Could not get analysis ID from VirusTotal API response",
            }

        # Wait for the analysis to complete (polling with exponential backoff)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        max_tries = 10
        for i in range(max_tries):
            logger.debug(f"Checking analysis status (attempt {i+1}/{max_tries})")
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                result_data = analysis_response.json()
                status = result_data.get("data", {}).get("attributes", {}).get("status")
                logger.debug(f"Analysis status: {status}")

                if status == "completed":
                    logger.debug("Analysis completed successfully")
                    return result_data
            else:
                logger.warning(
                    f"Error checking analysis status: {analysis_response.status_code}"
                )

            # Wait with exponential backoff before checking again
            sleep_time = 2**i
            logger.debug(f"Waiting {sleep_time} seconds before next check")
            time.sleep(sleep_time)

        logger.error("Analysis timed out")
        return {"error": True, "message": "Analysis timed out. Please try again later."}
    except Exception as e:
        logger.error(f"Error during file upload or analysis: {str(e)}")
        return {"error": True, "message": f"Error during analysis: {str(e)}"}


@app.route("/results")
def show_results():
    # Debug log to check session contents
    logger.debug(f"Session keys: {list(session.keys())}")

    if "scan_results" not in session:
        logger.warning("No scan results found in session")
        flash("No scan results found. Please upload a file first.", "warning")
        return redirect(url_for("index"))

    scan_results = session.get("scan_results")
    filename = session.get("filename", "Unknown file")
    file_hash = session.get("file_hash", "Unknown hash")

    # Debug log with minimal info to avoid sensitive data in logs
    logger.debug(f"Rendering results page for file: {filename}")

    return render_template(
        "results.html", results=scan_results, filename=filename, file_hash=file_hash
    )


# Add debug route to check session
@app.route("/debug/session")
def debug_session():
    if not config.DEBUG:
        return "Debug endpoints are not available in production mode", 403

    result = {
        "session_keys": list(session.keys()),
        "has_scan_results": "scan_results" in session,
        "has_filename": "filename" in session,
        "has_file_hash": "file_hash" in session,
    }

    # Add timestamp to verify if session is working
    session["debug_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return jsonify(result)


@app.errorhandler(413)
def request_entity_too_large(error):
    logger.warning("File upload exceeded size limit")
    flash(
        f'File too large. Maximum size is {app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)}MB',
        "danger",
    )
    return redirect(url_for("index"))


@app.errorhandler(404)
def page_not_found(error):
    logger.warning(f"404 error: {request.path}")
    return render_template("error.html", error="Page not found (404)"), 404


@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"500 error: {str(error)}")
    return render_template("error.html", error="Internal server error (500)"), 500


if __name__ == "__main__":
    logger.info("Starting Flask application")
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG)
