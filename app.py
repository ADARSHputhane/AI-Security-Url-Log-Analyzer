from flask import Flask, request, jsonify, render_template
from analyzer import analyze_url_threat, analyze_log_threat

app = Flask(__name__)


@app.route("/")
def home():
    # Flask automatically looks in the /templates folder
    return render_template("index.html")


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


if __name__ == "__main__":
    app.run(debug=True, port=5000)
