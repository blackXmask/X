import csv
import os
import random
from typing import List, Dict, Any, Optional

from config.features import FEATURES
from config.labels import LABEL_MAPPING, ATTACK_TO_LABEL
from config.settings import DATASET_SIZE, OUTPUT_FILE, DATA_DIR
from config.targets import load_targets_from_file
from generators.feature_extractor import FeatureExtractor

from engines import (
    SQLEngine, XSSEngine, SSREngine, PathTraversalEngine,
    AuthEngine, ReconEngine, APIAbuseEngine, NormalEngine
)

class DatasetGenerator:
    def __init__(self, targets: Optional[List[str]] = None):
        # Load or use provided targets
        self.targets = targets or load_targets_from_file()
        self.extractor = FeatureExtractor()
        
        # Initialize engines with random targets
        self.engines = {}
        for attack_type in ['sql', 'xss', 'ssrf', 'path_traversal', 
                           'auth_bypass', 'recon', 'api_abuse', 'normal']:
            target = random.choice(self.targets)
            self.engines[attack_type] = self._create_engine(attack_type, target)
        
        # Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)
    
    def _create_engine(self, attack_type: str, target: str):
        """Factory method to create engine with target"""
        engine_map = {
            'sql': SQLEngine,
            'xss': XSSEngine,
            'ssrf': SSREngine,
            'path_traversal': PathTraversalEngine,
            'auth_bypass': AuthEngine,
            'recon': ReconEngine,
            'api_abuse': APIAbuseEngine,
            'normal': NormalEngine
        }
        return engine_map[attack_type](base_url=target)
    
    def generate(self) -> str:
        all_samples = []
        
        # Generate samples from each engine
        for attack_type, count in DATASET_SIZE.items():
            print(f"Generating {count} samples for {attack_type}...")
            
            engine = self.engines.get(attack_type)
            if not engine:
                continue
            
            samples = engine.generate_samples(count)
            
            # Extract features and add label
            for sample in samples:
                features = self.extractor.extract(sample)
                
                # Map attack type to label
                attack_key = sample.get('attack_type', attack_type)
                label_name = ATTACK_TO_LABEL.get(attack_key, 'normal')
                label_id = LABEL_MAPPING[label_name]
                
                features['label'] = label_id
                features['label_name'] = label_name
                all_samples.append(features)
        
        # Shuffle samples
        random.shuffle(all_samples)
        
        # Write to CSV
        self._write_csv(all_samples)
        
        return OUTPUT_FILE
    
    def _write_csv(self, samples: List[Dict[str, Any]]):
        if not samples:
            print("No samples to write!")
            return
        
        fieldnames = FEATURES + ['label', 'label_name']
        
        with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(samples)
        
        print(f"\nDataset generated: {OUTPUT_FILE}")
        print(f"Total samples: {len(samples)}")
        self._print_statistics(samples)
    
    def _print_statistics(self, samples: List[Dict[str, Any]]):
        from collections import Counter
        labels = [s['label_name'] for s in samples]
        counts = Counter(labels)
        
        print("\nLabel distribution:")
        for label, count in sorted(counts.items()):
            print(f"  {label}: {count} ({count/len(samples)*100:.1f}%)")

if __name__ == '__main__':
    generator = DatasetGenerator()
    output_path = generator.generate()
    print(f"\nDone! Dataset saved to: {output_path}")