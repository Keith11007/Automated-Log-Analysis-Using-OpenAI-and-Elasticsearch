# Automated Log Analysis Using OpenAI and Elasticsearch

An automated log analysis system that uses **OpenAI** and **Elasticsearch** to collect, classify, search, and analyze security logs.

The system provides a dashboard where users can connect an Elasticsearch data source or upload log files, review log events, classify their severity, analyze suspicious activity using OpenAI, and check IP addresses using AbuseIPDB.

## Features

- Connect to Elasticsearch
- Upload log files
- Search and filter logs
- Classify logs as:
  - Critical
  - High Risk
  - Warning
  - Informational
- AI-powered log analysis using OpenAI
- Generate security insights and recommended actions
- IP reputation checking using AbuseIPDB
- View detailed information about selected logs
- Dashboard statistics for different log severity levels

## Technologies Used

- **Python**
- **Flask**
- **JavaScript**
- **HTML/CSS**
- **Elasticsearch**
- **OpenAI API**
- **AbuseIPDB API**

## Supported Log Files

The system supports:

- `.txt`
- `.log`
- `.json`
- `.jsonl`
- `.ndjson`
- `.csv`
and more.

## Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 4. Install the required packages

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Edit your `.env` file and add the required API credentials, including:

```env
OPENAI_API_KEY=your_openai_api_key
```
```env
ABUSEIPDB_API_KEY=ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### 6. Run the application

```bash
python main.py
```

The application runs on port **8000** by default.

Open the dashboard in your browser:

```text
http://localhost:8000
```


### Log Classification

OpenAI classifies logs into four categories:

- **Critical** – Active compromise, malware, exploitation, data loss, or urgent containment.
- **High** – Credible threats requiring prompt investigation.
- **Warning** – Suspicious, failed, blocked, error, or anomalous activity.
- **Info** – Normal or low-risk operational events.

The system also caches classification results to avoid repeatedly processing the same logs.

## Dashboard

The dashboard provides:

- Total log count
- Critical log count
- High-risk log count
- Warning count
- Log search
- Severity filtering
- Selected log details
- OpenAI analysis
- AbuseIPDB IP reputation checking

## OpenAI Analysis

The system allows an analyst to provide a prompt such as:

```text
Summarize the top risks in these logs and tell me what to investigate first.
```

OpenAI analyzes the available log data and provides a concise security assessment with recommended next steps.

## Project Structure

```text
Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch/
│
├── main.py
├── app_factory.py
├── requirements.txt
│
├── static/
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   └── js/
│       ├── state.js
│       ├── actions.js
│       └── ui.js
│
│
├── log_processing.py
├── settings.py
│
└── README.md
```

## Security

- API keys should be stored in environment variables rather than directly in source code.
- User-provided log data is escaped before being inserted into the dashboard to reduce the risk of XSS.
- Elasticsearch credentials should not be committed to the repository.

## Project Purpose

The purpose of this project is to reduce the manual effort involved in analyzing large volumes of log data by combining **log management, automated classification, threat intelligence, and AI-assisted security analysis** in one dashboard.

## Author

**Simiyu Chilton Keith**
