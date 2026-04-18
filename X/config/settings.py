import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'raw')

DATASET_SIZE = {
    'normal': 5000,
    'sql': 1500,
    'xss': 1500,
    'ssrf': 800,
    'path_traversal': 800,
    'auth_bypass': 600,
    'recon': 1000,
    'api_abuse': 600
}

OUTPUT_FILE = os.path.join(DATA_DIR, 'web_attack_dataset.csv')