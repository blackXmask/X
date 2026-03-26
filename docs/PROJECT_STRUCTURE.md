# Project Structure

## Directory Layout

```
AI_Project/
├── src/                          # Source code
│   ├── app.py                    # Flask web application
│   ├── data.py                   # Core vulnerability scanner
│   ├── scanner.py                # Scanner utilities
│   ├── baseline_engine.py        # Baseline comparison engine
│   ├── payload_mutation_engine.py # Payload mutation & bypassing
│   └── example_usage.py          # Usage examples
│
├── config/                       # Configuration files
│   └── config.json               # Main configuration
│
├── data/                         # Data storage
│   ├── ai_training_dataset.csv   # Training dataset
│   ├── dataset/                  # Additional datasets
│   ├── raw_responses/            # Captured responses
│   └── pics/                     # Screenshots/media
│
├── docs/                         # Documentation
│   ├── INDEX.md                  # Documentation index
│   ├── UPGRADE_SUMMARY.md        # Upgrade overview
│   ├── QUICK_REFERENCE.md        # Quick start guide
│   ├── UPGRADE_IMPLEMENTATION.md # Implementation details
│   ├── ARCHITECTURE_CHECKLIST.md # Architecture guide
│   ├── TROUBLESHOOTING.md        # Troubleshooting guide
│   ├── VISUAL_SUMMARY.md         # Visual architecture
│   └── DATA_REORGANIZATION.md    # Data layout explanation
│
├── templates/                    # Flask HTML templates
│   └── index.html                # Web interface
│
├── tests/                        # Test files
│
├── .git/                         # Git repository
├── .gitignore                    # Git ignore rules
├── README.md                     # Project overview
├── LICENSE                       # License file
├── flow.txt                      # Process flow
├── push.bat                      # Git push script
└── ai_training_dataset.csv       # Legacy dataset (root)


## Key Files

### Source Code (`src/`)
- **data.py**: Main VulnerabilityDataCollector class with:
  - BaselineEngine integration
  - PayloadMutationEngine integration
  - Exploit confirmation (≥2 signals required)
  - Confidence scoring (multi-factor)
  - 90+ dataset fields

- **baseline_engine.py**: Baseline creation & comparison:
  - Captures clean request baseline
  - Compares attack responses
  - Detects time anomalies (blind SQLi)
  - Detects content changes
  - Analyzes payload reflection

- **payload_mutation_engine.py**: Intelligent payload variants:
  - 10+ encoding strategies (URL, HTML, Unicode, etc)
  - Learning system tracking success rates
  - Context-aware mutations (XSS, SQLi, etc)
  - Filter bypass optimization

- **app.py**: Flask web interface:
  - Web-based scanning UI
  - Integrates with data.py
  - Serves static templates

- **scanner.py**: Scanner utilities:
  - Security header checks
  - Status code analysis
  - Server info detection
  - Cookie security validation

### Configuration (`config/`)
- **config.json**: Paths, payloads, and settings
  - `output.csv_file`: Points to `data/ai_training_dataset.csv`
  - `output.response_dir`: Points to `data/raw_responses`
  - `payloads`: XSS, SQLi, and custom payloads
  - All paths are relative to project root

### Data (`data/`)
- **ai_training_dataset.csv**: ML training data with 90+ fields
- **dataset/**: Additional training datasets
- **raw_responses/**: Captured HTTP responses for analysis
- **pics/**: Screenshots and media files

### Documentation (`docs/`)
Complete technical documentation with guides, API references, and troubleshooting


## Configuration Paths

All paths in `config/config.json` are relative to project root:

```json
{
  "output": {
    "csv_file": "data/ai_training_dataset.csv",
    "response_dir": "data/raw_responses",
    "save_raw_responses": true
  }
}
```

The Python files in `src/` use:
```json
config_path = "../config/config.json"
```

This allows the project root to be the reference point for all relative paths.


## Running the Project

### Flask Web App
```bash
cd src
python app.py
# Access at http://localhost:5000
```

### Command-line Scanner
```bash
cd src
python -c "import asyncio; from example_usage import scan_url_advanced; asyncio.run(scan_url_advanced('http://target.com'))"
```

### Direct Usage
```python
import sys
sys.path.insert(0, 'src')
from data import VulnerabilityDataCollector

# Initialize with config location
collector = VulnerabilityDataCollector('../config/config.json')
```


## Import Structure

All modules in `src/` can import from each other:
```python
from baseline_engine import BaselineEngine
from payload_mutation_engine import PayloadMutationEngine
from data import VulnerabilityDataCollector
```

Configuration is loaded relative to config.json location:
```python
config_path = "../config/config.json"  # From src/ perspective
```


## Next Steps

1. ✅ Complete project restructuring (directories created)
2. ✅ Move Python files to src/ (baseline_engine.py, etc)
3. ✅ Move documentation to docs/ 
4. ✅ Move configuration to config/
5. ✅ Update config paths in Python files
6. ⏳ Create tests/ with unit tests
7. ⏳ Add requirements.txt with dependencies
8. ⏳ Consider adding CI/CD configuration

