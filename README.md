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
- [Contributing](#contributing)


---

## Overview

Our system improves traditional web vulnerability detection by integrating an XGBoost model that learns patterns in malicious inputs, reducing false positives and improving detection accuracy. The platform is named **Platform X**, reflecting its advanced, intelligent approach to web application security.
---

### Key Capabilities

| Capability                  | Description                                                                                                        |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------- |
| **Automated Analysis**      | Advanced HTTP request inspection with in-depth response behavior profiling                                         |
| **AI-Powered Detection**    | XGBoost-based model trained on real-world vulnerability patterns for accurate threat identification                |
| **Comprehensive Reporting** | Detailed security insights with CVSS-inspired severity classification and actionable findings                      |
| **Web-Based Interface**     | Intuitive and responsive Flask-powered UI for efficient interaction and visualization                              |
| **Hybrid Detection Engine** | Combines rule-based techniques with machine learning predictions for enhanced accuracy and reduced false positives |



---

## Key Features

### 🔍 Core Detection Engine

* **Multi-Protocol Support**: Handles HTTP/1.1, HTTP/2, and WebSocket communication
* **Comprehensive Method Coverage**: Supports GET, POST, PUT, DELETE, OPTIONS, PATCH, and HEAD requests
* **Advanced Response Analysis**: Detects timing anomalies, content inconsistencies, and status code irregularities
* **Security Header Evaluation**: Validates configurations like CSP, HSTS, X-Frame-Options, and CORS policies
* **Cookie Security Analysis**: Assesses Secure, HttpOnly, SameSite attributes, and expiration policies
* **Technology Fingerprinting**: Identifies server technologies and potential version exposures

---

### 🤖 Machine Learning Module

* **Intelligent Vulnerability Classification**: Detects threats such as XSS, SQL Injection, SSRF, RCE, LFI/RFI, and CSRF
* **Behavioral Anomaly Detection**: Learns and identifies unusual response patterns beyond static rules
* **Confidence-Based Scoring**: Assigns probability-driven risk scores (0–100%) for each finding
* **Adaptive Learning**: Supports model retraining using newly generated scan data
* **Automated Feature Engineering**: Extracts and processes security-relevant features for improved model performance

---

### 🌐 Web Application Interface

* **Real-Time Monitoring**: Live scan updates using WebSocket-based communication
* **Interactive Dashboard**: Dynamic, filterable, and sortable results for efficient analysis
* **Visual Analytics**: Graphical representation of vulnerability trends and distribution
* **Flexible Export Options**: Generate reports in PDF, CSV, JSON, and HTML formats
* **Scan History Management**: Enables comparison of previous scans and trend analysis over time


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
