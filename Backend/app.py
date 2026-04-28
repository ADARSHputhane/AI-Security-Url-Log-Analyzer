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

# CORS origins — override via ALLOWED_ORIGINS env var (comma-separated)
_raw_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
)
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ALLOWED_ORIGINS,
            "methods": ["GET", "POST"],
        }
    },
)

# File upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv", "log", "txt"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_INPUT_LENGTH = 2000            # chars — cap strings sent to the model

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_json_body():
    """Return parsed JSON body or None; never raises."""
    try:
        return request.get_json(force=False, silent=True) or {}
    except Exception:
        return {}


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    data = get_json_body()
    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if len(url) > MAX_INPUT_LENGTH:
        return jsonify({"error": "URL exceeds maximum allowed length"}), 400
    try:
        return jsonify({"url": url, **analyze_url_threat(url)})
    except Exception:
        return jsonify({"error": "Analysis failed. Check server logs."}), 500


@app.route("/api/analyze-log", methods=["POST"])
def api_analyze_log():
    data = get_json_body()
    log_entry = str(data.get("log", "")).strip()
    if not log_entry:
        return jsonify({"error": "Log entry is required"}), 400
    if len(log_entry) > MAX_INPUT_LENGTH:
        return jsonify({"error": "Log entry exceeds maximum allowed length"}), 400
    try:
        return jsonify({"log": log_entry, **analyze_log_threat(log_entry)})
    except Exception:
        return jsonify({"error": "Analysis failed. Check server logs."}), 500


@app.route("/api/upload-csv", methods=["POST"])
def upload_csv():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename) or not file.filename.endswith(".csv"):
        return jsonify({"error": "File must be a CSV file"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)
    try:
        results = analyze_csv_file(filepath)
        return jsonify({"filename": filename, "total_rows": len(results), "results": results}), 200
    except Exception:
        return jsonify({"error": "CSV analysis failed. Check server logs."}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/api/upload-log", methods=["POST"])
def upload_log():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename) or not file.filename.endswith((".log", ".txt")):
        return jsonify({"error": "File must be a LOG or TXT file"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)
    try:
        results = analyze_log_file(filepath)
        return jsonify({"filename": filename, "total_lines": len(results), "results": results}), 200
    except Exception:
        return jsonify({"error": "Log analysis failed. Check server logs."}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="0.0.0.0", port=5000)
