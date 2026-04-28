from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import (
    analyze_url_threat,
    analyze_log_threat,
    analyze_csv_file,
    analyze_log_file,
)
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
# Allow requests from your Next.js local server
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://192.168.0.103:3000",
            ],
            "methods": ["GET", "POST"],
        }
    },
)

# File upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv", "log", "txt"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    data = request.json
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    try:
        return jsonify({"url": url, **analyze_url_threat(url)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze-log", methods=["POST"])
def api_analyze_log():
    data = request.json
    log_entry = data.get("log", "")
    if not log_entry:
        return jsonify({"error": "Log entry is required"}), 400
    try:
        return jsonify({"log": log_entry, **analyze_log_threat(log_entry)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/upload-csv", methods=["POST"])
def upload_csv():
    """Upload and analyze a CSV file"""
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename) or not file.filename.endswith(".csv"):
        return jsonify({"error": "File must be a CSV file"}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        results = analyze_csv_file(filepath)

        # Clean up uploaded file
        os.remove(filepath)

        return (
            jsonify(
                {"filename": filename, "total_rows": len(results), "results": results}
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": f"CSV analysis failed: {str(e)}"}), 500


@app.route("/api/upload-log", methods=["POST"])
def upload_log():
    """Upload and analyze a LOG file"""
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename) or not file.filename.endswith((".log", ".txt")):
        return jsonify({"error": "File must be a LOG or TXT file"}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        results = analyze_log_file(filepath)

        # Clean up uploaded file
        os.remove(filepath)

        return (
            jsonify(
                {"filename": filename, "total_lines": len(results), "results": results}
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": f"Log analysis failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
