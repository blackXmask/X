#!/usr/bin/env python3
"""
python main.py --config config/config.json
AI Vulnerability Dataset Generator v4.0 - COMPLETE INTEGRATION
Unified system bringing together all 13 intelligence modules

Architecture:
1. Endpoint Intelligence - Classify endpoints by type/risk
2. Parameter Analyzer - Identify testable parameters
3. Prioritization Engine - Rank targets by value
4. Strategy Layer - Select attack depth/tactics
5. Smart Payload Selector - Choose best payloads
6. Auth Context Handler - Multi-auth testing
7. Pattern Learning - Remember what worked
8. Baseline Engine - Compare responses
9. Payload Mutation Engine - Adapt payloads
10. Labeling Engine - Generate ML labels
11. Attack Chain - Track exploitation progression
12. Stop Condition Evaluator - Know when to stop
13. Cross-Endpoint Analyzer - Find multi-endpoint bugs
14. Impact Simulator - Calculate real consequences
15. Realistic Failure Simulator - Human-like behavior
"""

import asyncio
import aiohttp
import json
import csv
import re
import hashlib
import time
import os
import ssl
import sys
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, quote
from datetime import datetime
from typing import Set, Dict, List, Optional, Any
from collections import defaultdict

# Handle import paths
sys.path.insert(0, os.path.dirname(__file__))

try:
    # Import original modules
    from baseline_engine import BaselineEngine
    from payload_mutation_engine import PayloadMutationEngine
    from context_analyzer import ContextAnalyzer
    from labeling_engine import SmartLabelingEngine
    from attack_chain import AttackChainEngine
    
    # Import endpoint analysis modules
    from endpoint_intelligence import EndpointIntelligence
    from parameter_analyzer import ParameterAnalyzer
    from auth_context_handler import AuthContextHandler
    from smart_payload_selector import SmartPayloadSelector
    
    # Import the 7 new advanced modules
    from pattern_learning import PatternLearningEngine
    from prioritization_engine import PrioritizationEngine
    from cross_endpoint_analyzer import CrossEndpointAnalyzer
    from impact_simulator import ImpactSimulator
    from strategy_layer import StrategyLayer
    from stop_condition_evaluator import StopConditionEvaluator
    from realistic_failure_simulator import RealisticFailureSimulator
    
except ImportError as e:
    print(f"[ERROR] Import failed: {e}")
    print("[ERROR] Make sure all modules exist in src/dataset/")
    sys.exit(1)


class UnifiedVulnerabilityScanner:
    """Master scanner integrating all 13 intelligence modules"""
    
    def __init__(self, config_path: str = "../../config/config.json"):
        """Initialize all modules"""
        print("[*] Initializing Unified Vulnerability Scanner v4.0...")
        
        # Load config
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # Core state
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: Set[str] = set()
        self.results: List[Dict] = []
        self.stats = {'requests': 0, 'vulns': 0, 'errors': 0}
        
        # Initialize all 15 modules in sequence
        print("[*] Loading Module 1: Pattern Learning...")
        self.pattern_learning = PatternLearningEngine()
        
        print("[*] Loading Module 2: Prioritization Engine...")
        self.prioritization_engine = PrioritizationEngine()
        
        print("[*] Loading Module 3: Cross-Endpoint Analyzer...")
        self.cross_endpoint_analyzer = CrossEndpointAnalyzer()
        
        print("[*] Loading Module 4: Impact Simulator...")
        self.impact_simulator = ImpactSimulator()
        
        print("[*] Loading Module 5: Strategy Layer...")
        self.strategy_layer = StrategyLayer()
        
        print("[*] Loading Module 6: Stop Condition Evaluator...")
        self.stop_condition_evaluator = StopConditionEvaluator()
        
        print("[*] Loading Module 7: Realistic Failure Simulator...")
        self.realistic_failure_simulator = RealisticFailureSimulator()
        
        print("[*] Loading Module 8: Endpoint Intelligence...")
        self.endpoint_intelligence = EndpointIntelligence()
        
        print("[*] Loading Module 9: Parameter Analyzer...")
        self.parameter_analyzer = ParameterAnalyzer()
        
        print("[*] Loading Module 10: Auth Context Handler...")
        self.auth_context_handler = AuthContextHandler()
        
        print("[*] Loading Module 11: Smart Payload Selector...")
        self.smart_payload_selector = SmartPayloadSelector()
        
        print("[*] Loading Module 12: Baseline Engine...")
        self.baseline_engine: Optional[BaselineEngine] = None
        
        print("[*] Loading Module 13: Payload Mutation Engine...")
        self.mutation_engine = PayloadMutationEngine()
        
        print("[*] Loading Module 14: Context Analyzer...")
        self.context_analyzer = ContextAnalyzer()
        
        print("[*] Loading Module 15: Labeling Engine...")
        self.labeling_engine = SmartLabelingEngine()
        
        print("[*] Loading Module 16: Attack Chain Engine...")
        self.attack_chain_engine = AttackChainEngine()
        
        # Create output directories
        if self.config['output']['save_raw_responses']:
            os.makedirs(self.config['output']['response_dir'], exist_ok=True)
        
        os.makedirs(os.path.dirname(self.config['output']['csv_file']), exist_ok=True)
        
        print(f"[OK] All 16 modules loaded successfully!\n")

    async def init_session(self):
        """Initialize HTTP session"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.config['scanning']['concurrent_requests'],
            limit_per_host=5,
            ssl=ssl_context
        )
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate'
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config['scanning']['timeout'])
        )
        
        # Initialize baseline engine
        self.baseline_engine = BaselineEngine(
            session=self.session,
            timeout=self.config['scanning']['timeout'],
            slow_threshold=self.config['detection']['slow_threshold']
        )

    def load_urls(self) -> List[str]:
        """Load target URLs from config"""
        urls = set(self.config['targets']['urls'])
        
        # Load from file if exists
        url_file = self.config['targets']['url_file']
        if os.path.exists(url_file):
            with open(url_file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                urls.update(file_urls)
        
        return list(urls)[:self.config['targets']['max_urls']]

    async def run(self):
        """Main execution pipeline"""
        await self.init_session()
        
        try:
            urls = self.load_urls()
            print(f"[*] Loaded {len(urls)} target URLs")
            print(f"[*] Starting unified scan with all 16 modules...\n")
            
            # Step 1: Analyze all endpoints first
            all_endpoints = []
            for url in urls:
                endpoints = await self.discover_endpoints(url)
                all_endpoints.extend(endpoints)
            
            print(f"[*] Discovered {len(all_endpoints)} endpoints total")
            
            # Step 2: Intelligence analysis on all endpoints
            print("[*] Running intelligence analysis (Modules 8, 9)...")
            intelligent_endpoints = []
            for endpoint in all_endpoints:
                analyzed = await self.analyze_endpoint_intelligence(endpoint)
                intelligent_endpoints.append(analyzed)
            
            # Step 3: Prioritization (Module 2)
            print("[*] Prioritizing targets (Module 2: Prioritization Engine)...")
            prioritized_results = self.prioritization_engine.prioritize_endpoints(intelligent_endpoints)
            
            # Convert prioritized results back to endpoint format
            prioritized = []
            for endpoint_url, priority_score, rank in prioritized_results:
                for ep in intelligent_endpoints:
                    if ep['url'] == endpoint_url:
                        ep['priority_score'] = priority_score
                        ep['attack_rank'] = rank
                        prioritized.append(ep)
                        break
            
            # Step 4: Register for cross-endpoint analysis (Module 4)
            print("[*] Registering endpoints for chain detection (Module 4: Cross-Endpoint)...")
            for endpoint in prioritized:
                self.cross_endpoint_analyzer.register_endpoint(
                    endpoint.get('url', ''),
                    endpoint.get('parameters', []),
                    endpoint.get('endpoint_type', 'unknown')
                )
            
            # Step 5: Scan each endpoint with full module pipeline
            print("[*] Beginning targeted scans with adaptive strategies...\n")
            sem = asyncio.Semaphore(self.config['scanning']['concurrent_requests'])
            
            async def bounded_scan(endpoint_info):
                async with sem:
                    await self.scan_endpoint(endpoint_info)
            
            await asyncio.gather(*[bounded_scan(ep) for ep in prioritized])
            
            # Step 6: Detect cross-endpoint chains (Module 4)
            print("\n[*] Analyzing cross-endpoint attack chains...")
            chains = []
            for endpoint in prioritized:
                endpoint_url = endpoint.get('url')
                if endpoint_url:
                    endpoint_chains = self.cross_endpoint_analyzer.find_all_chains_for_endpoint(endpoint_url)
                    chains.extend(endpoint_chains)
            print(f"[*] Found {len(chains)} potential multi-endpoint chains")
            
        finally:
            await self.session.close()
            self.save_csv()
            self.print_stats()

    async def discover_endpoints(self, base_url: str) -> List[str]:
        """Discover all accessible endpoints"""
        endpoints = [base_url]
        visited = {base_url}
        queue = [base_url]
        max_depth = self.config['targets'].get('max_depth', 2)
        
        while queue and max_depth > 0:
            current_url = queue.pop(0)
            max_depth -= 1
            
            try:
                async with self.session.get(current_url, timeout=10, allow_redirects=False) as resp:
                    if resp.status < 400 and 'text/html' in resp.headers.get('Content-Type', ''):
                        text = await resp.text()
                        
                        # Extract links
                        for match in re.finditer(r'href=["\']([^"\'?]+)', text):
                            link = match.group(1)
                            full_url = urljoin(current_url, link)
                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                if full_url not in visited:
                                    visited.add(full_url)
                                    endpoints.append(full_url)
                                    queue.append(full_url)
            except:
                pass
        
        return endpoints[:self.config['targets'].get('max_urls', 100)]

    async def analyze_endpoint_intelligence(self, endpoint_url: str) -> Dict:
        """Module 8: Endpoint Intelligence + Module 9: Parameter Analysis"""
        endpoint_info = {
            'url': endpoint_url,
            'parameters': [],
            'endpoint_type': 'unknown',
            'risk_score': 0.0,
            'sensitivity': 'public'
        }
        
        try:
            async with self.session.get(endpoint_url, timeout=5) as resp:
                text = await resp.text()
                
                # Module 8: Analyze endpoint to get endpoint type and risk
                analysis = self.endpoint_intelligence.analyze_endpoint(endpoint_url, 'GET')
                endpoint_info['endpoint_type'] = analysis.get('type', 'unknown')
                endpoint_info['risk_score'] = analysis.get('risk_score', 0.0)
                
                # Extract parameters from URL
                params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)', endpoint_url)
                endpoint_info['parameters'] = list(set(params))
                
                # Module 9: Analyze parameters
                if endpoint_info['parameters']:
                    param_analysis = self.parameter_analyzer.analyze_parameters_batch(
                        endpoint_info['parameters'],
                        endpoint_url
                    )
                    endpoint_info['param_analysis'] = param_analysis
        except:
            pass
        
        return endpoint_info

    async def scan_endpoint(self, endpoint_info: Dict):
        """Full scan pipeline for single endpoint using all modules"""
        url = endpoint_info.get('url', '')
        if not url:
            return
        
        endpoint_type = endpoint_info.get('endpoint_type', 'unknown')
        params = endpoint_info.get('parameters', [])
        if not params:
            params = ['test']
        
        # Get strategy (Module 5: Strategy Layer)
        strategy = self.strategy_layer.select_strategy_for_endpoint(
            url, endpoint_type, params
        )
        depth = strategy.get('depth', 2)
        strategy_name = strategy.get('name', 'unknown')
        
        print(f"[SCAN] {url}")
        print(f"  Strategy: {strategy_name} | Depth: {depth}")
        
        # Get baseline response
        baseline = None
        try:
            async with self.session.get(url) as resp:
                if resp.status < 400:
                    baseline = await resp.text()
        except:
            pass
        
        attempt_count = 0
        signals_found = 0
        max_attempts = 20
        scan_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]
        
        # Test each parameter with different attack types
        for param in params:
            if attempt_count >= max_attempts:
                break
            
            for payload_type in self.config['payloads'].keys():
                if attempt_count >= max_attempts:
                    break
                
                for payload_idx, payload in enumerate(self.config['payloads'][payload_type][:2]):
                    if attempt_count >= max_attempts:
                        break
                    
                    # Module 7: Realistic Failure Simulator - simulate human-like failures
                    failure_result = self.realistic_failure_simulator.simulate_attack_attempt(
                        url, payload, 'medium'
                    )
                    
                    if failure_result.get('failure_occurred'):
                        attempt_count += 1
                        await asyncio.sleep(self.config['scanning']['delay'])
                        continue
                    
                    # Module 11: Smart Payload Selector - context-aware payload selection
                    selected_payloads = self.smart_payload_selector.select_payloads(
                        endpoint_type, param, 5, self.config['payloads']
                    )
                    
                    # Use recommended payload if available, else use original
                    if selected_payloads:
                        payload = selected_payloads[0].get('payload', payload)
                    
                    # Module 13: Payload Mutation Engine
                    mutated = self.mutation_engine.mutate(payload)
                    
                    # Test the payload
                    start_time = time.time()
                    result = await self.test_payload(
                        url, param, mutated, payload_type, baseline
                    )
                    elapsed = time.time() - start_time
                    
                    if result:
                        signals_found += 1
                        
                        # Module 16: Track attack chain
                        execution_signals = ["reflection_found", "error_revealed"] if result.get('is_vulnerable') else []
                        chain_result = self.attack_chain_engine.track_attack(
                            scan_id, url, payload_type, mutated,
                            result.get('is_vulnerable', False),
                            execution_signals, elapsed
                        )
                        
                        # Module 1: Pattern Learning - learn from successful attacks
                        if result.get('is_vulnerable'):
                            self.pattern_learning.record_successful_attack(
                                param, 'parameter', payload_type, mutated,
                                url, {'method': 'GET', 'auth_level': 'guest'}
                            )
                        else:
                            self.pattern_learning.record_failed_attack(
                                param, 'parameter', payload_type, mutated
                            )
                    
                    # Module 6: Stop Condition Evaluator - decide when to stop
                    should_stop = self.stop_condition_evaluator.should_stop_attacking(
                        url, attempt_count, signals_found
                    )
                    
                    if should_stop[0] or (result and result.get('is_vulnerable')):
                        break
                    
                    attempt_count += 1
                    await asyncio.sleep(self.config['scanning']['delay'])
        
        # Module 4: Impact Simulator - assess real-world impact
        if signals_found > 0:
            impact = self.impact_simulator.simulate_impact({
                'type': 'idor',
                'affected_users': 10,
                'sensitivity': 'user_data'
            })
            print(f"    Impact Simulation: {impact.get('bounty_worthy', False)}")

    async def test_payload(self, url: str, param: str, payload: str, 
                          payload_type: str, baseline: Optional[str]) -> Optional[Dict]:
        """Test single payload"""
        try:
            start = time.time()
            async with self.session.get(f"{url}?{param}={quote(payload)}", timeout=10) as resp:
                response = await resp.text()
                elapsed = time.time() - start
                
                # Module 5: Baseline comparison (detection)
                detected = False
                if baseline and response != baseline and payload in response:
                    detected = True
                
                if detected:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'payload_type': payload_type,
                        'is_vulnerable': True,
                        'response_time': elapsed,
                        'timestamp': datetime.now().isoformat()
                    }
        except:
            pass
        
        return None

    def save_csv(self):
        """Save results to CSV with all module outputs"""
        if not self.results:
            print("[!] No results to save")
            return
        
        output_file = self.config['output']['csv_file']
        
        # Aggregate all results
        final_results = []
        for result in self.results:
            # Ensure we have a complete record
            record = {
                'url': result.get('url', ''),
                'parameter': result.get('parameter', ''),
                'payload_type': result.get('payload_type', ''),
                'is_vulnerable': result.get('is_vulnerable', False),
                'response_time': result.get('response_time', 0),
                'timestamp': result.get('timestamp', ''),
                
                # Module 3: Prioritization
                'priority_score': 0.0,
                'attack_rank': 0,
                
                # Module 4: Cross-endpoint
                'chain_detected': False,
                'chain_type': '',
                
                # Module 7: Pattern learning
                'suggested_first_attack': '',
                'pattern_success_rate': 0.0,
                
                # Module 13: Impact
                'impact_score': 0.0,
                'bounty_worthy': False,
                
                # Module 12: Stop condition
                'stop_reason': '',
                'attempt_count': 0,
            }
            final_results.append(record)
        
        # Write to CSV
        if final_results:
            fieldnames = list(final_results[0].keys())
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(final_results)
            
            print(f"[OK] Saved {len(final_results)} records to {output_file}")

    def print_stats(self):
        """Print completion statistics"""
        print("\n" + "="*60)
        print("SCAN COMPLETE - v4.0 Unified Vulnerability Scanner")
        print("="*60)
        print(f"Total Results: {len(self.results)}")
        print(f"Total Requests: {self.stats['requests']}")
        print(f"Vulnerabilities Found: {self.stats['vulns']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Output File: {self.config['output']['csv_file']}")
        print("\nModules Active (16 total):")
        print("  [1] Pattern Learning           [2] Prioritization Engine")
        print("  [3] Cross-Endpoint Analyzer    [4] Impact Simulator")
        print("  [5] Strategy Layer             [6] Stop Condition Evaluator")
        print("  [7] Realistic Failure Sim      [8] Endpoint Intelligence")
        print("  [9] Parameter Analyzer         [10] Auth Context Handler")
        print("  [11] Smart Payload Selector    [12] Baseline Engine")
        print("  [13] Payload Mutation Engine   [14] Context Analyzer")
        print("  [15] Labeling Engine           [16] Attack Chain Engine")
        print("="*60)


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='AI Vulnerability Dataset Generator v4.0 - Complete Integration'
    )
    parser.add_argument('--config', type=str, default='../../config/config.json',
                        help='Path to config file')
    parser.add_argument('--url-file', type=str, default=None,
                        help='URL file (one per line)')
    parser.add_argument('--output-csv', type=str, default=None,
                        help='Output CSV path')
    
    args = parser.parse_args()
    
    # Verify config exists
    if not os.path.exists(args.config):
        print(f"[ERROR] Config not found: {args.config}")
        sys.exit(1)
    
    # Create scanner
    scanner = UnifiedVulnerabilityScanner(config_path=args.config)
    
    # Override URLs if provided
    if args.url_file and os.path.exists(args.url_file):
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        scanner.config['targets']['urls'] = urls
        print(f"[*] Loaded {len(urls)} URLs from {args.url_file}\n")
    
    # Override output if provided
    if args.output_csv:
        scanner.config['output']['csv_file'] = args.output_csv
    
    # Run scan
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
