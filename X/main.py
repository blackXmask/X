#!/usr/bin/env python3
"""
Web Attack Detection - Dataset Generator
Main entry point for generating training datasets
"""

import sys
import argparse
from generators.dataset_generator import DatasetGenerator

def main():
    parser = argparse.ArgumentParser(
        description='Generate web attack detection dataset'
    )
    parser.add_argument(
        '--size', '-s',
        type=int,
        default=None,
        help='Override total dataset size'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='Output CSV file path'
    )
    parser.add_argument(
        '--target', '-t',
        type=str,
        action='append',
        help='Target URL (can use multiple times)'
    )
    parser.add_argument(
        '--targets-file', '-f',
        type=str,
        help='File with target URLs (one per line)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Web Attack Detection - Dataset Generator")
    print("=" * 60)
    
    # Load targets
    targets = None
    if args.target:
        targets = args.target
        print(f"Using {len(targets)} target(s) from command line")
    elif args.targets_file:
        with open(args.targets_file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"Loaded {len(targets)} target(s) from {args.targets_file}")
    else:
        from config.targets import load_targets_from_file
        targets = load_targets_from_file()
        print(f"Using {len(targets)} default target(s)")
    
    print(f"Targets: {targets[:3]}..." if len(targets) > 3 else f"Targets: {targets}")
    
    # Override settings
    if args.size:
        from config import settings
        ratio = args.size / sum(settings.DATASET_SIZE.values())
        settings.DATASET_SIZE = {
            k: int(v * ratio) for k, v in settings.DATASET_SIZE.items()
        }
    
    if args.output:
        from config import settings
        settings.OUTPUT_FILE = args.output
    
    # Generate
    try:
        generator = DatasetGenerator(targets=targets)
        output_path = generator.generate()
        print(f"\n✅ Success! Dataset saved to: {output_path}")
        return 0
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())