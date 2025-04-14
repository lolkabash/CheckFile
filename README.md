# CheckFile (VirusTotal File Scanner)

A Flask-based web application that allows users to upload files and scan them using the VirusTotal API.

## Features

- File Upload Interface: Simple and intuitive web interface for uploading files
- VirusTotal API Integration: Scans uploaded files for malware and viruses
- Dynamic Results Display: Clear presentation of scan results (in alphabetical order of AntiVirus)
- Security Measures: File validation, size limits, and secure file handling
- Responsive Design: Works well on both desktop and mobile devices
- CSRF protection is enabled to prevent cross-site request forgery attacks

## Prerequisites

- Python 3.8 or higher
- AWS EC2 instance for hosting (or any other hosting service)
- VirusTotal API key
## Project Structure
```
CheckFile/
│
├── app.py                 # Main Flask application
├── config.py              # Configuration file
├── templates/
│   ├── index.html         # Upload form
│   ├── results.html       # Scan results
│   ├── base.html          # Base template
│   └── error.html         # Error page
├── static/
│   ├── css/
│   │   └── style.css      # Custom styles
│   └── js/
│       └── main.js        # JavaScript for dynamic features
├── requirements.txt       # Dependencies
└── README.md              # Documentation
```
## Installation and Setup

### Local Development

1. Clone the repository:
   ```
   git clone https://github.com/lolkabash/CheckFile.git
   cd virus-scanner
   ```

2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
   On Windows: 
   ```
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```
   export VIRUSTOTAL_API_KEY='your_api_key_here'
   export SECRET_KEY='your_secret_key_here'
   export DEBUG='True'
   ```

   On Windows:
   ```
   set VIRUSTOTAL_API_KEY=your_api_key_here
   set SECRET_KEY=your_secret_key_here
   set DEBUG=True
   ```

4. Run the development server:
   ```
   python app.py
   ```

5. Access the application at http://localhost:5000

## Usage

1. Open the application in a web browser.
2. Click the "Choose File" button to select a file for scanning.
3. Click the "Scan File" button to upload the file and initiate the scan.
4. Wait for the scanning process to complete.
5. View the detailed scan results, including:
   - Detection rates from multiple antivirus engines
   - File information and hash values
   - Specific threats detected (if any)

## Security Considerations

- File uploads are validated for type and size before processing.
- Uploaded files are stored temporarily and deleted after scanning.
- API keys and sensitive information are stored as environment variables.
- Input is sanitized to prevent malicious execution.
- Added CSRFProtect to initialize CSRF protection for all forms.

## Customization

- Change the theme by modifying the CSS in `static/css/style.css`.
- Add additional file validations in the `upload_file` route.
- Extend the results display to show more detailed information from the VirusTotal API.
### File Upload Configuration

You can control which file types are allowed for upload by setting the `ALLOWED_EXTENSIONS` environment variable:

- To allow `"txt","pdf","png","jpg","jpeg","gif","doc","docx","xls","xlsx","exe"` file types (default), leave `ALLOWED_EXTENSIONS` empty or unset
- To restrict to specific file types, set a comma-separated list of file extensions: `ALLOWED_EXTENSIONS=txt,pdf,png,jpg,jpeg,gif,doc,docx,xls,xlsx,exe`

Note that allowing certain file types could potentially increase security risks, but all files are scanned before processing and are deleted immediately after scanning.
## Troubleshooting

- If the application fails to start, check the log files for errors:
  ```
  sudo journalctl -u virus-scanner.service
  ```

- If you encounter "API key error" messages, verify your VirusTotal API key is correctly set in the environment variables.

- For upload issues, check that your file sizes are within the allowed limits (16MB by default).

## License

[MIT License](LICENSE)