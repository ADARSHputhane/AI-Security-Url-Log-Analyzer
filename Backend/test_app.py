"""
Backend test suite — models are mocked so no GPU/download required.
Run with: pytest test_app.py -v
"""
import io
import json
import os
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Patch model loading BEFORE importing the modules under test so the real
# pipeline() call never fires during test collection.
# ---------------------------------------------------------------------------
def make_url_classifier(label, score):
    mock = MagicMock()
    mock.return_value = [{"label": label, "score": score}]
    return mock


def make_log_classifier(labels, scores):
    mock = MagicMock()
    mock.return_value = {"labels": labels, "scores": scores}
    return mock


@pytest.fixture(autouse=True)
def patch_pipelines():
    with patch(
        "analyzer.url_classifier",
        make_url_classifier("LABEL_0", 0.97),
    ), patch(
        "analyzer.log_classifier",
        make_log_classifier(
            ["Normal Web Traffic", "SQL Injection Attack"],
            [0.91, 0.06],
        ),
    ):
        yield


# Import after patches are in place
import analyzer
from app import app as flask_app


# ---------------------------------------------------------------------------
# Shared test client
# ---------------------------------------------------------------------------
@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ===========================================================================
# 1. Unit tests — analyzer.py
# ===========================================================================


class TestAnalyzeUrlThreat:
    def test_benign_url_returns_safe_label(self):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_0", 0.97)):
            result = analyzer.analyze_url_threat("https://google.com")
        assert result["prediction"] == "BENIGN (SAFE)"
        assert result["confidence"] == 97.0

    def test_phishing_url_returns_malicious_label(self):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_3", 0.88)):
            result = analyzer.analyze_url_threat("http://evil-phish.ru/login")
        assert "MALICIOUS" in result["prediction"]
        assert result["confidence"] == 88.0

    def test_malware_url_label(self):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_2", 0.75)):
            result = analyzer.analyze_url_threat("http://malware-site.xyz")
        assert result["prediction"] == "MALWARE (MALICIOUS)"

    def test_defacement_url_label(self):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_1", 0.60)):
            result = analyzer.analyze_url_threat("http://hacked-site.com")
        assert result["prediction"] == "DEFACEMENT (MALICIOUS)"

    def test_unknown_label_falls_back_to_raw(self):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_99", 0.50)):
            result = analyzer.analyze_url_threat("http://unknown.com")
        assert result["prediction"] == "LABEL_99"

    def test_confidence_rounded_to_two_decimals(self):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_0", 1 / 3)):
            result = analyzer.analyze_url_threat("https://example.com")
        assert result["confidence"] == 33.33


class TestAnalyzeLogThreat:
    def test_normal_traffic_detected(self):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.92]),
        ):
            result = analyzer.analyze_log_threat("GET /index.html HTTP/1.1")
        assert result["prediction"] == "Normal Web Traffic"
        assert result["confidence"] == 92.0

    def test_sql_injection_detected(self):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(
                ["SQL Injection Attack", "Normal Web Traffic"], [0.89, 0.07]
            ),
        ):
            result = analyzer.analyze_log_threat("GET /page?id=1' OR '1'='1")
        assert result["prediction"] == "SQL Injection Attack"

    def test_xss_detected(self):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(
                ["Cross-Site Scripting (XSS)", "Normal Web Traffic"], [0.85, 0.10]
            ),
        ):
            result = analyzer.analyze_log_threat(
                "GET /search?q=<script>alert(1)</script>"
            )
        assert result["prediction"] == "Cross-Site Scripting (XSS)"

    def test_brute_force_detected(self):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(
                ["Brute Force Login Attempt", "Normal Web Traffic"], [0.78, 0.15]
            ),
        ):
            result = analyzer.analyze_log_threat(
                "POST /login failed password attempt 50 times"
            )
        assert result["prediction"] == "Brute Force Login Attempt"


class TestAnalyzeCsvFile:
    def test_url_column_analyzed_as_url(self, tmp_path):
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("url\nhttps://google.com\nhttps://evil.com\n")
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_0", 0.95)):
            results = analyzer.analyze_csv_file(str(csv_file))
        assert len(results) == 2
        assert results[0]["threat_analysis"][0]["type"] == "URL"
        assert results[0]["row_number"] == 1

    def test_log_column_analyzed_as_log_entry(self, tmp_path):
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("log_entry\nGET /index.html\nSELECT * FROM users\n")
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.90]),
        ):
            results = analyzer.analyze_csv_file(str(csv_file))
        assert results[0]["threat_analysis"][0]["type"] == "LOG_ENTRY"

    def test_nan_values_skipped(self, tmp_path):
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("url\nhttps://example.com\n\n")
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_0", 0.90)):
            results = analyzer.analyze_csv_file(str(csv_file))
        assert len(results) == 1

    def test_invalid_file_raises_exception(self):
        with pytest.raises(Exception, match="Failed to process CSV file"):
            analyzer.analyze_csv_file("/nonexistent/path/file.csv")


class TestAnalyzeLogFile:
    def test_each_line_analyzed(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(
            "GET /index.html HTTP/1.1\nGET /admin.php?id=1 OR 1=1\n"
        )
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.91]),
        ):
            results = analyzer.analyze_log_file(str(log_file))
        assert len(results) == 2
        assert results[0]["line_number"] == 1
        assert results[1]["line_number"] == 2

    def test_empty_lines_skipped(self, tmp_path):
        log_file = tmp_path / "sparse.log"
        log_file.write_text("line one\n\n\nline four\n")
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.91]),
        ):
            results = analyzer.analyze_log_file(str(log_file))
        assert len(results) == 2

    def test_invalid_file_raises_exception(self):
        with pytest.raises(Exception, match="Failed to process log file"):
            analyzer.analyze_log_file("/nonexistent/path/file.log")


# ===========================================================================
# 2. Integration tests — Flask API endpoints
# ===========================================================================


class TestAnalyzeUrlEndpoint:
    def test_valid_url_returns_200(self, client):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_0", 0.95)):
            resp = client.post(
                "/api/analyze-url",
                json={"url": "https://google.com"},
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["url"] == "https://google.com"
        assert "prediction" in data
        assert "confidence" in data

    def test_missing_url_returns_400(self, client):
        resp = client.post("/api/analyze-url", json={})
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_malicious_url_flagged(self, client):
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_3", 0.88)):
            resp = client.post(
                "/api/analyze-url",
                json={"url": "http://phishing-site.xyz"},
            )
        data = resp.get_json()
        assert "MALICIOUS" in data["prediction"]


class TestAnalyzeLogEndpoint:
    def test_valid_log_returns_200(self, client):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.92]),
        ):
            resp = client.post(
                "/api/analyze-log",
                json={"log": "GET /index.html HTTP/1.1"},
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["log"] == "GET /index.html HTTP/1.1"
        assert "prediction" in data

    def test_missing_log_returns_400(self, client):
        resp = client.post("/api/analyze-log", json={})
        assert resp.status_code == 400

    def test_sql_injection_classified(self, client):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["SQL Injection Attack"], [0.90]),
        ):
            resp = client.post(
                "/api/analyze-log",
                json={"log": "SELECT * FROM users WHERE id=1 OR 1=1"},
            )
        assert resp.get_json()["prediction"] == "SQL Injection Attack"


class TestUploadCsvEndpoint:
    def test_valid_csv_returns_200(self, client):
        csv_content = b"url\nhttps://example.com\nhttps://test.com\n"
        with patch("analyzer.url_classifier", make_url_classifier("LABEL_0", 0.95)):
            resp = client.post(
                "/api/upload-csv",
                data={"file": (io.BytesIO(csv_content), "data.csv")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["filename"] == "data.csv"
        assert data["total_rows"] == 2

    def test_no_file_returns_400(self, client):
        resp = client.post("/api/upload-csv")
        assert resp.status_code == 400

    def test_wrong_extension_returns_400(self, client):
        resp = client.post(
            "/api/upload-csv",
            data={"file": (io.BytesIO(b"data"), "data.txt")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400

    def test_empty_filename_returns_400(self, client):
        resp = client.post(
            "/api/upload-csv",
            data={"file": (io.BytesIO(b""), "")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400


class TestUploadLogEndpoint:
    def test_valid_log_file_returns_200(self, client):
        log_content = b"GET /index.html HTTP/1.1\nPOST /login HTTP/1.1\n"
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.91]),
        ):
            resp = client.post(
                "/api/upload-log",
                data={"file": (io.BytesIO(log_content), "access.log")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_lines"] == 2

    def test_txt_extension_accepted(self, client):
        with patch(
            "analyzer.log_classifier",
            make_log_classifier(["Normal Web Traffic"], [0.91]),
        ):
            resp = client.post(
                "/api/upload-log",
                data={"file": (io.BytesIO(b"some log line\n"), "log.txt")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200

    def test_csv_extension_rejected(self, client):
        resp = client.post(
            "/api/upload-log",
            data={"file": (io.BytesIO(b"data"), "data.csv")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400

    def test_no_file_returns_400(self, client):
        resp = client.post("/api/upload-log")
        assert resp.status_code == 400
