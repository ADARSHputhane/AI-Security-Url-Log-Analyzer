from transformers import pipeline
import logging
import pandas as pd

logging.getLogger("transformers").setLevel(logging.ERROR)

print("Loading Hugging Face models...")

url_classifier = pipeline(
    "text-classification", model="Eason918/malicious-url-detector", truncation=True
)

log_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

LOG_CATEGORIES = [
    "Normal Web Traffic",
    "SQL Injection Attack",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Brute Force Login Attempt",
]


def analyze_url_threat(url):
    # The raw result from the Hugging Face model
    result = url_classifier(url)[0]
    raw_label = result["label"]

    # Our custom translator dictionary
    label_mapping = {
        "LABEL_0": "BENIGN (SAFE)",
        "LABEL_1": "DEFACEMENT (MALICIOUS)",
        "LABEL_2": "MALWARE (MALICIOUS)",
        "LABEL_3": "PHISHING (MALICIOUS)",
    }

    # Translate the label, or fallback to the raw label if it's not found
    human_readable_prediction = label_mapping.get(raw_label, raw_label)

    return {
        "prediction": human_readable_prediction,
        "confidence": round(result["score"] * 100, 2),
    }


def analyze_log_threat(log_entry):
    result = log_classifier(log_entry, candidate_labels=LOG_CATEGORIES)
    return {
        "prediction": result["labels"][0],
        "confidence": round(result["scores"][0] * 100, 2),
    }


def analyze_csv_file(filepath):
    """
    Analyze a CSV file and return threat analysis for each row.
    Supports columns containing URLs, IPs, or log entries.
    """
    try:
        df = pd.read_csv(filepath)
        results = []

        # Get column names
        columns = df.columns.tolist()

        for idx, row in df.iterrows():
            row_analysis = {"row_number": idx + 1, "data": {}, "threat_analysis": []}

            # Analyze each column
            for col in columns:
                value = str(row[col]).strip()

                if not value or value.lower() == "nan":
                    continue

                # Store original data
                row_analysis["data"][col] = value

                # Try to detect what type of data this is and analyze accordingly
                analysis = None

                # Check if it looks like a URL
                if value.startswith(("http://", "https://", "ftp://")):
                    try:
                        analysis = {
                            "column": col,
                            "value": value,
                            "type": "URL",
                            **analyze_url_threat(value),
                        }
                    except:
                        pass

                # If not a URL, treat as log entry
                if analysis is None:
                    try:
                        analysis = {
                            "column": col,
                            "value": value,
                            "type": "LOG_ENTRY",
                            **analyze_log_threat(value),
                        }
                    except:
                        pass

                if analysis:
                    row_analysis["threat_analysis"].append(analysis)

            results.append(row_analysis)

        return results

    except Exception as e:
        raise Exception(f"Failed to process CSV file: {str(e)}")


def analyze_log_file(filepath):
    """
    Analyze a LOG file and return threat analysis for each line.
    Skips empty lines and processes non-empty entries.
    """
    try:
        results = []
        line_number = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and lines with only whitespace
                if not line:
                    continue

                line_number += 1

                try:
                    analysis = {
                        "line_number": line_number,
                        "log_entry": line,
                        **analyze_log_threat(line),
                    }
                    results.append(analysis)
                except Exception as e:
                    results.append(
                        {"line_number": line_number, "log_entry": line, "error": str(e)}
                    )

        return results

    except Exception as e:
        raise Exception(f"Failed to process log file: {str(e)}")
