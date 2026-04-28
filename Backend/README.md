# AI-Powered Threat Intelligence Dashboard 🛡️

A full-stack web application designed to analyze suspicious URLs and detect anomalous server logs using local, pre-trained Hugging Face Transformer models.

This tool serves as a lightweight, AI-driven assistant for Security Operations Centers (SOC) to automate initial threat triage.

## 🚀 Features

- **URL Phishing & Malware Analysis:** Utilizes a fine-tuned DistilBERT model to classify URLs into categories: Benign, Defacement, Malware, or Phishing. Includes custom tensor label mapping for accurate human-readable outputs.
- **Zero-Shot Log Anomaly Detection:** Leverages `facebook/bart-large-mnli` for dynamic server log classification. It evaluates raw HTTP requests against predefined threat vectors like SQL Injection, XSS, Directory Traversal, and Brute Force attempts without requiring a custom-trained dataset.
- **Local Inference:** Models are downloaded and run entirely locally via PyTorch, ensuring no sensitive log data is transmitted to external third-party APIs.
- **Modular Architecture:** Clean separation of concerns between the Flask routing server (`app.py`), the Machine Learning pipeline (`analyzer.py`), and the frontend interface.

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Machine Learning:** Hugging Face `transformers`, PyTorch (CPU-optimized inference)
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, FontAwesome
- **Environment Management:** Anaconda

## ⚙️ Installation & Setup

### Prerequisites

- Anaconda or Miniconda installed on your system.

### 1. Clone the repository

```bash
git clone [https://github.com/yourusername/ai-security-dashboard.git](https://github.com/yourusername/ai-security-dashboard.git)
cd ai-security-dashboard
```

### 2. Create env

```bash
conda env create -f environment.yml
conda activate ai-security-env
```

### 3. Run the Application

```bash
python3 app.py
```

### 4. Access the Dashboard

```bash
http://127.0.0.1:5000
```

#### 🧠 Example Test Cases

- Test a Malicious URL:
  http://secure-update-billing-verify.com/login.php .

- Test an SQL Injection Log:
  10.0.0.5 - - [28/Apr/2026:14:05:12 +0000] "POST /login HTTP/1.1" 200 "admin' OR

#### 🛡️ Security & Privacy Notice

- Because this application runs inference locally via PyTorch, it acts as a privacy-first tool. Organizations can safely pipe internal logs into this analyzer without risking data exposure to external cloud providers.

```bash
### Next Steps for GitHub
Once you have saved your `.gitignore` and `README.md`, you are ready to upload.
1. Run `git init` (if you haven't already).
2. Run `git add .`
3. Run `git commit -m "Initial commit: Flask UI and Hugging Face pipelines"`
4. Push to your repository!
```
