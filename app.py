from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect  # Import CSRF protection
import os
import hashlib
import requests
import time
from datetime import timedelta
from werkzeug.utils import secure_filename
import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["UPLOAD_FOLDER"] = config.UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH  # 16MB max file size
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["ALLOWED_EXTENSIONS"] = config.ALLOWED_EXTENSIONS
app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # Set CSRF token expiration to 1 hour

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Create upload folder if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename):
    """Check if a file has an allowed extension."""
    # If ALLOWED_EXTENSIONS is None, allow all extensions
    if app.config["ALLOWED_EXTENSIONS"] is None:
        return True

    # Otherwise, check if the file extension is in the allowed set
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


@app.route("/", methods=["GET"])
def index():
    # Pass the allowed extensions to the template for display
    allowed_extensions = app.config["ALLOWED_EXTENSIONS"]
    return render_template("index.html", allowed_extensions=allowed_extensions)


@app.route("/upload", methods=["POST"])
def upload_file():
    # Check if a file was submitted
    if "file" not in request.files:
        flash("No file part", "danger")
        return redirect(url_for("index"))

    file = request.files["file"]

    # If the user does not select a file, browser submits an empty file without a filename
    if file.filename == "":
        flash("No selected file", "danger")
        return redirect(url_for("index"))

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

        # Scan with VirusTotal API
        scan_results = scan_file_with_virustotal(filepath, file_hash)

        # Store results in session to display on results page
        session["scan_results"] = scan_results
        session["filename"] = filename
        session["file_hash"] = file_hash

        # Clean up - remove the file after scanning
        os.remove(filepath)

        return redirect(url_for("show_results"))
    else:
        if app.config["ALLOWED_EXTENSIONS"] is None:
            flash("File type not allowed.", "danger")
        else:
            flash(
                f'File type not allowed. Allowed types: {", ".join(app.config["ALLOWED_EXTENSIONS"])}',
                "danger",
            )
        return redirect(url_for("index"))


@app.route("/results")
def show_results():
    if "scan_results" not in session:
        flash("No scan results found. Please upload a file first.", "warning")
        return redirect(url_for("index"))

    scan_results = session.get("scan_results")
    filename = session.get("filename", "Unknown file")
    file_hash = session.get("file_hash", "Unknown hash")

    return render_template(
        "results.html", results=scan_results, filename=filename, file_hash=file_hash
    )


# CSRF error handler
@app.errorhandler(400)
def handle_csrf_error(e):
    flash("The form has expired. Please try again.", "danger")
    return redirect(url_for("index"))


@app.errorhandler(413)
def request_entity_too_large(error):
    flash(
        f'File too large. Maximum size is {app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)}MB',
        "danger",
    )
    return redirect(url_for("index"))


@app.errorhandler(405)
def method_not_allowed_error(error):
    """Handle 405 Method Not Allowed errors."""
    flash(
        "The method is not allowed for the requested URL. Please try again.", "danger"
    )
    return redirect(url_for("index"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("error.html", error="Page not found (404)"), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("error.html", error="Internal server error (500)"), 500


def scan_file_with_virustotal(filepath, file_hash):
    api_key = config.VIRUSTOTAL_API_KEY

    if not api_key:
        return {
            "error": True,
            "message": "VirusTotal API key is missing. Please set the VIRUSTOTAL_API_KEY environment variable.",
        }

    headers = {"x-apikey": api_key}

    # First check if the file has been scanned before
    check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response = requests.get(check_url, headers=headers)

        if response.status_code == 200:
            # File was scanned before, return the results

            # Add a small delay to simulate scanning and ensure UI updates properly
            time.sleep(2)

            # For previously scanned files, we need to ensure the data structure is consistent
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

            return result_data
        elif response.status_code == 401:
            return {
                "error": True,
                "message": "API authentication error. Please check your VirusTotal API key.",
            }
        elif response.status_code == 404:
            # Continue with upload since file wasn't found
            pass
        else:
            return {
                "error": True,
                "message": f"Unexpected response from VirusTotal API: {response.status_code}",
            }
    except Exception as e:
        return {
            "error": True,
            "message": f"Error connecting to VirusTotal API: {str(e)}",
        }

    # If file wasn't scanned before, upload it and scan
    upload_url = "https://www.virustotal.com/api/v3/files"

    try:
        with open(filepath, "rb") as file:
            files = {"file": (os.path.basename(filepath), file)}
            upload_response = requests.post(upload_url, headers=headers, files=files)

        if upload_response.status_code != 200:
            return {
                "error": True,
                "message": f"Error uploading file: {upload_response.status_code}",
            }

        # Get the analysis ID from the upload response
        upload_json = upload_response.json()

        if "data" not in upload_json:
            return {
                "error": True,
                "message": "Unexpected response format from VirusTotal API during upload",
            }

        analysis_id = upload_json.get("data", {}).get("id")

        if not analysis_id:
            return {
                "error": True,
                "message": "Could not get analysis ID from VirusTotal API response",
            }

        # Wait for the analysis to complete (polling with exponential backoff)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        max_tries = 10
        for i in range(max_tries):
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                result_data = analysis_response.json()
                status = result_data.get("data", {}).get("attributes", {}).get("status")

                if status == "completed":
                    return result_data

            # Wait with exponential backoff before checking again
            sleep_time = 2**i
            time.sleep(sleep_time)

        return {"error": True, "message": "Analysis timed out. Please try again later."}
    except Exception as e:
        return {"error": True, "message": f"Error during analysis: {str(e)}"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
