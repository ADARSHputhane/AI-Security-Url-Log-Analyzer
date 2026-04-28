from transformers import pipeline
import logging

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
