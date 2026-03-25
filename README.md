<div align="center">

# X
### AI-Powered Web Security Testing Platform
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-000000?logo=xgboost&logoColor=white)](https://xgboost.ai/)
[![License](https://img.shields.io/badge/License-red)](LICENSE)


<p align="center"><i>Vulnerability detection with machine learning intelligence</i></p>

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Project Roadmap](#project-roadmap)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Contributing](#contributing)


---

## Overview

This project is an **AI-powered web vulnerability scanner** developed as a **4th Semester Final Year Project**. It combines traditional rule-based security testing with modern machine learning techniques to detect potential vulnerabilities in web applications.

### Key Capabilities

| Capability | Description |
|:-----------|:------------|
| **Automated Scanning** | Intelligent HTTP request analysis with comprehensive response profiling |
| **AI Detection** | Machine learning models trained on real-world vulnerability patterns |
| **Comprehensive Reports** | Detailed security assessments with CVSS-style severity classifications |
| **Web Interface** | Clean, responsive Flask-based UI for seamless user interaction |
| **Dual Engine** | Hybrid approach combining rule-based checks and ML predictions |

---

## Key Features

### 🔍 Core Scanning Engine

- **Multi-Protocol Testing**: HTTP/1.1, HTTP/2, WebSocket support
- **Method Coverage**: GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD
- **Response Analysis**: Timing attacks, content length anomalies, status code patterns
- **Header Security**: X-Frame-Options, CSP, HSTS, CORS policy validation
- **Cookie Analysis**: Secure, HttpOnly, SameSite, expiration checks
- **Fingerprinting**: Server technology detection and version identification

### 🤖 Machine Learning Module

- **Vulnerability Classification**: XSS, SQL Injection, SSRF, RCE, LFI/RFI, CSRF
- **Anomaly Detection**: Behavioral analysis of response patterns
- **Confidence Scoring**: Probability-based risk assessment (0-100%)
- **Continuous Learning**: Model retraining from new scan datasets
- **Feature Engineering**: Automated extraction of security-relevant features

### 🌐 Web Application Interface

- **Real-time Monitoring**: Live scan progress with WebSocket updates
- **Interactive Dashboard**: Sortable, filterable results table
- **Visual Analytics**: Charts for vulnerability distribution and trends
- **Export Options**: PDF, CSV, JSON, HTML report generation
- **History Management**: Previous scan comparison and trending

---

## System Architecture

```

┌─────────────────────────────────────────────────────────────────────────────┐
│                           PRESENTATION LAYER                                │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │   Web Interface  │    │   API Gateway    │    │   Report Viewer  │       │
│  │   (Flask/Jinja2) │◄──►│   (REST/WS)      │◄──►│   (Exportable)   │       │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘       │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APPLICATION LAYER                                   │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │  Request Router  │◄──►│  Scan Controller │◄──►│  Auth Manager    │       │
│  │  (URL Validation)│    │  (Job Queue)     │    │  (Session/Token) │       │
│  └──────────────────┘    └────────┬─────────┘    └──────────────────┘       │
└─────────────────────────────────────┼───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SCANNING ENGINE                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     HTTP Client Module                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │    │
│  │  │   Request    │  │   Response   │  │   Cookie     │  │ Redirect │ │    │
│  │  │   Builder    │  │   Parser     │  │   Handler    │  │ Handler  │ │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────┘ │    │ 
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    Rule-Based Analyzer                              │    │
│  │  • Security Headers Check    • HTTP Method Allowlist                │    │
│  │  • Information Disclosure    • SSL/TLS Configuration                │    │
│  │  • Cookie Security           • CORS Policy Validation               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MACHINE LEARNING LAYER                                │
│                                                                             │
│   Feature Extraction Pipeline                                               │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────┐     │
│   │   Numeric    │   │  Categorical │   │   Text       │   │  Binary  │     │
│   │   Features   │   │  Encoders    │   │   Vectorizer │   │  Flags   │     │
│   │ (time/size)  │   │(header types)│   │ (response)   │   │(present) │     │
│   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └────┬─────┘     │
│          └──────────────────┴──────────────────┴────────────────┘           │
│                                      │                                      │
│   Model Inference                    │                                      │
│   ┌──────────────────────────────────┴──────────────────────────────────┐   │
│   │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌────────┐   │   │
│   │  │   Random    │   │   Gradient  │   │   Neural    │   │ Voting │   │   │
│   │  │   Forest    │   │   Boosting  │   │   Network   │   │Ensemble│   │   │
│   │  │  (sklearn)  │   │   (XGBoost) │   │ (TF/PyTorch)│   │        │   │   │
│   │  └─────────────┘   └─────────────┘   └─────────────┘   └────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│   Output: Vulnerability Class + Confidence Score + Affected Parameters      │
│                                                                             │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DATA & REPORTING LAYER                               │
│                                                                             │
│   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│   │   Data Storage   │    │   Report Engine  │    │   Export Module  │      │
│   │   (SQLite/CSV)   │    │   (Jinja2/PDF)   │    │   (Multi-format) │      │
│   └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                                             │
│   Severity Classification:                                                  │
🔴 Critical (9.0-10.0)  🟠 High (7.0-8.9)  🟡 Medium (4.0-6.9)  🟢 Low (0-3.9) 
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Roadmap

### Phase 1: Foundation Engine ✅
*Core backend infrastructure and rule-based scanning*

| Component | Status | Priority | Description |
|:----------|:------:|:--------:|:------------|
| HTTP Scanner Core | ✅ | High | Multi-method request engine with timeout handling |
| Response Parser | ✅ | High | Header, cookie, and body extraction |
| Rule-Based Checks | ✅ | High | Security header and configuration validation |
| Data Persistence | ✅ | Medium | Structured CSV/JSON storage layer |
| Error Handling | ✅ | High | Robust exception management and logging |

### Phase 2: Intelligence Dataset 🔄
*Training data generation and preprocessing pipeline*

| Component | Status | Priority | Description |
|:----------|:------:|:--------:|:------------|
| Test Target Integration | 🔄 | High | DVWA, Juice Shop, WebGoat connectivity |
| Data Collection Agent | 🔄 | High | Automated scan and response capture |
| Feature Engineering | 🔄 | Critical | Numeric encoding and normalization |
| Labeling System | 🔄 | Critical | Ground truth vulnerability tagging |
| Dataset Balancing | ⏳ | Medium | Oversampling/undersampling for rare classes |

### Phase 3: ML Model Training ⏳
*AI model development, training, and evaluation*

| Component | Status | Priority | Description |
|:----------|:------:|:--------:|:------------|
| Baseline Models | ⏳ | High | Logistic Regression, Decision Trees |
| Advanced Models | ⏳ | High | Random Forest, XGBoost, Neural Networks |
| Hyperparameter Tuning | ⏳ | Medium | Grid search and Bayesian optimization |
| Model Evaluation | ⏳ | Critical | Cross-validation, ROC-AUC, F1-score |
| Model Export | ⏳ | High | ONNX/Pickle format for production |

### Phase 4: Integration & UI ⏳
*System unification and interface enhancement*

| Component | Status | Priority | Description |
|:----------|:------:|:--------:|:------------|
| Flask API Development | ⏳ | High | RESTful endpoints for all operations |
| Frontend Redesign | ⏳ | Medium | Bootstrap 5 / React modern UI |
| Results Dashboard | ⏳ | Medium | Interactive data visualization |
| Report Generator | ⏳ | Medium | PDF/HTML export with charts |
| User Authentication | ⏳ | Low | Multi-user support with roles |

### Phase 5: Advanced Features 📋
*Intelligent assistant and automation capabilities*

| Component | Status | Priority | Description |
|:----------|:------:|:--------:|:------------|
| NLP Chatbot | 📋 | Low | Natural language query interface |
| Explanation Engine | 📋 | Medium | SHAP/LIME model interpretability |
| Remediation Advisor | 📋 | Medium | Auto-generated security fix suggestions |
| CI/CD Integration | 📋 | Low | GitHub Actions/Jenkins plugin |
| Distributed Scanning | 📋 | Low | Multi-node scanning architecture |

**Legend:** ✅ Complete | 🔄 In Progress | ⏳ Planned | 📋 Future


---

## 📊 Dataset Schema

The generated CSV contains **50+ engineered features** optimized for ML vulnerability detection models [^5^][^10^]:

### 🆔 Identification & Metadata
| Column | Type | Description |
|:---------|:-----|:------------|
| `scan_id` | string | Unique 12-char hash per test |
| `timestamp` | ISO8601 | Test execution time |
| `dataset_version` | string | Schema version (e.g., "1.0") |
| `depth_level` | int | Crawler depth (0=seed) |

### 🎯 Target Information
| Column | Type | Description |
|:---------|:-----|:------------|
| `target_url` | string | Full tested URL |
| `base_domain` | string | Extracted domain |
| `endpoint_path` | string | URL path component |
| `is_api_endpoint` | bool | Auto-detected REST/JSON API |

### 📡 Request Details
| Column | Type | Description |
|:---------|:-----|:------------|
| `http_method` | categorical | GET, POST, PUT |
| `tested_parameter` | string | Parameter name tested |
| `payload` | string | Raw payload sent |
| `payload_type` | categorical | sqli, xss, command, path_traversal, ssrf, idor, xxe, ssti |
| `payload_encoded` | string | URL-encoded payload |
| `attack_vector` | categorical | url_param, body, client_side |

### 📥 Response Metrics
| Column | Type | Description |
|:---------|:-----|:------------|
| `response_status` | int | HTTP status code |
| `response_time_ms` | float | Round-trip time (milliseconds) |
| `response_size_bytes` | int | Content length |
| `response_hash` | string | SHA256 prefix (content fingerprint) |
| `content_type` | string | MIME type |

### 🔒 Security Headers
| Column | Type | Description |
|:---------|:-----|:------------|
| `header_x_frame` | string | X-Frame-Options value |
| `header_csp` | string | Content-Security-Policy |
| `header_hsts` | string | Strict-Transport-Security |
| `header_x_content_type` | string | X-Content-Type-Options |
| `header_xss_protection` | string | X-XSS-Protection |
| `header_referrer` | string | Referrer-Policy |
| `header_cors` | string | Access-Control-Allow-Origin |
| `server_tech` | string | Server header fingerprint |
| `secure_headers_present` | bool | Aggregate security score |

### 🍪 Cookie Analysis
| Column | Type | Description |
|:---------|:-----|:------------|
| `cookie_secure_flag` | bool | Secure attribute present |
| `cookie_httponly_flag` | bool | HttpOnly attribute present |
| `cookie_samesite` | categorical | none, lax, strict |
| `cookie_count` | int | Number of cookies set |

### 🚨 Vulnerability Detection (Target Variables)
| Column | Type | Description |
|:---------|:-----|:------------|
| `vulnerability_detected` | bool | Ground truth label |
| `vulnerability_type` | categorical | Specific vulnerability class |
| `vulnerability_severity` | categorical | critical, high, medium, low, info |
| `confidence_score` | float | 0.0-1.0 probability |
| `evidence` | string | Detection reason/description |
| `false_positive_risk` | categorical | low, medium, high |
| `exploit_confirmed` | bool | High-confidence exploitable |

### 🤖 ML Feature Vectors
| Column | Type | Description |
|:---------|:-----|:------------|
| `text_features` | string | NLP-ready cleaned text (first 500 chars) |
| `error_pattern_matches` | string | Detected error signatures |
| `numeric_features_vector` | JSON | 12-dimensional numeric array |
| `categorical_features_vector` | JSON | Encoded categorical values |
| `semantic_structure_hash` | string | DOM structure fingerprint |
| `payload_fingerprint` | string | Payload hash for deduplication |

### 📈 Behavioral Analysis
| Column | Type | Description |
|:---------|:-----|:------------|
| `payload_reflected` | bool | Payload appears in response |
| `payload_transformed` | bool | Payload encoded/decoded in response |
| `status_changed` | bool | Differs from baseline |
| `content_changed` | bool | Hash differs from baseline |
| `baseline_size_diff` | int | Byte difference from baseline |
| `time_anomaly` | bool | Response time > threshold |

### 🌐 Context Flags
| Column | Type | Description |
|:---------|:-----|:------------|
| `requires_authentication` | bool | 401 response detected |
| `is_redirect` | bool | 3xx status code |
| `is_error_page` | bool | 4xx/5xx status |

### 📝 Debug Data (Optional)
| Column | Type | Description |
|:---------|:-----|:------------|
| `response_preview` | string | First 500 chars (sanitized) |
| `request_headers` | string | Sent headers log |
| `form_params_count` | int | Discovered form inputs |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Windows/Linux/macOS
- Target URLs list (optional)

### Installation

```bash

# 1. Clone repository
git clone https://github.com/blackXmask/vulnerability-data-collector.git
cd vulnerability-data-collector

# 2. Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
# Activate (Linux/Mac)
source venv/bin/activate

# 3. Install dependencies
pip install aiohttp aiofiles beautifulsoup4

# 4. Create config.json (see Configuration section)

```

### Docker Deployment (Optional) 

```bash
# Build image
docker build -t ai-vuln-scanner .

# Run container
docker run -p 5000:5000 ai-vuln-scanner
```

---

## Usage

### Web Interface

1. **Access Application**: Open `http://localhost:5000` in your browser
2. **Configure Scan**:
   - Enter target URL (e.g., `https://example.com`)
   - Select scan profile: Quick / Standard / Deep / Custom
   - Toggle AI analysis (requires trained model)
3. **Execute Scan**: Click "Start Scan" and monitor progress
4. **Review Results**: Analyze findings by severity and category
5. **Export Report**: Download in PDF, CSV, or JSON format



```
### Configuration

Edit `config.py` to customize:

```python
# Scanning behavior
MAX_THREADS = 10
REQUEST_TIMEOUT = 30
USER_AGENT = "AI-Vuln-Scanner/1.0"

# ML settings
MODEL_PATH = "models/rf_classifier_v1.pkl"
CONFIDENCE_THRESHOLD = 0.75

# Reporting
DEFAULT_FORMAT = "json"
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14", 
    "medium": "#ffc107",
    "low": "#28a745"
}
```

---

## API Reference

### Authentication

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "secure_password"
}
```

### Start Scan

```http
POST /api/v1/scans
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_url": "https://example.com",
  "scan_type": "deep",
  "ai_analysis": true,
  "callback_url": "https://your-server.com/webhook"
}
```

**Response:**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "estimated_duration": "120s",
  "created_at": "2024-03-22T23:48:00Z"
}
```

### Get Results

```http
GET /api/v1/scans/{scan_id}/results
Authorization: Bearer <token>
```

**Response:**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "summary": {
    "total_requests": 150,
    "vulnerabilities_found": 12,
    "severity_breakdown": {
      "critical": 2,
      "high": 3,
      "medium": 5,
      "low": 2
    }
  },
  "findings": [
    {
      "id": 1,
      "type": "SQL Injection",
      "severity": "critical",
      "confidence": 0.94,
      "location": "/search?q=1' OR '1'='1",
      "description": "Time-based blind SQL injection detected",
      "remediation": "Use parameterized queries and prepared statements"
    }
  ]
}
```


## Contributing

This project is developed for academic purposes. While direct contributions are limited, feedback and suggestions are welcome.


### Code Standards

- **PEP 8** compliance (enforced via `flake8`)
- **Type hints** for all function signatures
- **Docstrings** following Google style
- **Unit tests** for new features (min 80% coverage)

---

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only.

- Always obtain **written permission** before scanning target systems
- Respect **rate limits** and avoid overwhelming target servers
- **Never** use against production systems without approval
- Follow **responsible disclosure** for any vulnerabilities found
- Check local laws regarding security testing and computer access

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|:------|:---------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| Database locked | Ensure no other process is using `scanner.db` |
| Model not found | Train model first: `python train_model.py` |
| Scan timeouts | Increase `REQUEST_TIMEOUT` in config |
| Memory errors | Reduce `MAX_THREADS` for large scans |

### Support

- **Documentation**: Check `/docs` directory
- **Issues**: GitHub Issues (academic inquiries only)
- **Email**: 24pwcys***@uetpeshawar.com/blackxmask.official.com


---

## Acknowledgments

- **OWASP Foundation** for security guidelines and testing resources
- **PortSwigger Web Security** for methodology references
- **Scikit-learn & TensorFlow Teams** for ML framework support
- **University Supervisor** for project guidance and mentorship

---

<div align="center">

**[⬆ Back to Top](#-ai-vulnerability-scanner--bug-bounty-tool)**

Built with precision for academic excellence 🎓

</div>
