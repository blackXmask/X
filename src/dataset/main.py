#!/usr/bin/env python3
"""
python main.py --config config/config.json
AI Vulnerability Dataset Generator v4.0 - FIXED VERSION
All critical issues resolved for proper ML dataset generation

Fixes Applied:
1. ✅ Save ALL results (not just vulnerable) - CRITICAL FIX
2. ✅ Calculate proper anomaly_score
3. ✅ Enhanced detection logic (reflection, error, similarity, time, status)
4. ✅ Better parameter coverage
5. ✅ JSON export added
6. ✅ Proper negative samples for ML training
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
import math
from urllib.parse import urlparse, urljoin, parse_qs, quote
from datetime import datetime
from typing import Set, Dict, List, Optional, Any
from collections import defaultdict

# Handle import paths
sys.path.insert(0, os.path.dirname(__file__))

try:
    from baseline_engine import BaselineEngine
    from payload_mutation_engine import PayloadMutationEngine
    from context_analyzer import ContextAnalyzer
    from labeling_engine import SmartLabelingEngine
    from attack_chain import AttackChainEngine
    
    from endpoint_intelligence import EndpointIntelligence
    from parameter_analyzer import ParameterAnalyzer
    from auth_context_handler import AuthContextHandler
    from smart_payload_selector import SmartPayloadSelector
    
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
    """Master scanner with ML-quality dataset generation"""
    
    def __init__(self, config_path: str = "../../config/config.json"):
        """Initialize all modules"""
        print("[*] Initializing Unified Vulnerability Scanner v4.0 (FIXED)...")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: Set[str] = set()
        self.results: List[Dict] = []  # ALL results go here now
        self.stats = {'requests': 0, 'vulns': 0, 'errors': 0, 'waf_triggers': 0, 'saved': 0}
        self.strategy_history: List[str] = []
        
        # Initialize all 16 modules
        print("[*] Loading 16 intelligence modules...")
        self.pattern_learning = PatternLearningEngine()
        self.prioritization_engine = PrioritizationEngine()
        self.cross_endpoint_analyzer = CrossEndpointAnalyzer()
        self.impact_simulator = ImpactSimulator()
        self.strategy_layer = StrategyLayer()
        self.stop_condition_evaluator = StopConditionEvaluator()
        self.realistic_failure_simulator = RealisticFailureSimulator()
        self.endpoint_intelligence = EndpointIntelligence()
        self.parameter_analyzer = ParameterAnalyzer()
        self.auth_context_handler = AuthContextHandler()
        self.smart_payload_selector = SmartPayloadSelector()
        self.baseline_engine: Optional[BaselineEngine] = None
        self.mutation_engine = PayloadMutationEngine()
        self.context_analyzer = ContextAnalyzer()
        self.labeling_engine = SmartLabelingEngine()
        self.attack_chain_engine = AttackChainEngine()
        
        # Create output directories
        if self.config['output']['save_raw_responses']:
            os.makedirs(self.config['output']['response_dir'], exist_ok=True)
        
        os.makedirs(os.path.dirname(self.config['output']['csv_file']), exist_ok=True)
        
        print(f"[OK] All modules loaded successfully!\n")

    async def init_session(self):
        """Initialize HTTP session with connection pooling"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.config['scanning']['concurrent_requests'],
            limit_per_host=10,
            ttl_dns_cache=self.config['scanning'].get('ttl_dns_cache', 300),
            enable_cleanup_closed=self.config['scanning'].get('enable_cleanup_closed', True),
            force_close=self.config['scanning'].get('force_close', False),
            ssl=ssl_context
        )
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'DNT': '1'
        }
        
        timeout = aiohttp.ClientTimeout(
            total=self.config['scanning']['timeout'],
            connect=10,
            sock_read=self.config['scanning']['timeout']
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=timeout
        )
        
        self.baseline_engine = BaselineEngine(
            session=self.session,
            timeout=self.config['scanning']['timeout'],
            slow_threshold=self.config['detection']['slow_threshold']
        )

    def load_urls(self) -> List[str]:
        """Load target URLs from config"""
        urls = set()
        
        for url in self.config['targets']['urls']:
            url = url.strip()
            if url:
                urls.add(url)
        
        url_file = self.config['targets']['url_file']
        if os.path.exists(url_file):
            with open(url_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.add(line)
        
        return list(urls)[:self.config['targets']['max_urls']]

    async def fetch_with_retry(self, url: str, method: str = 'GET', data: Any = None, 
                              headers: Optional[Dict] = None, max_retries: int = 3) -> Optional[aiohttp.ClientResponse]:
        """Fetch URL with exponential backoff"""
        for attempt in range(max_retries):
            try:
                if method == 'GET':
                    async with self.session.get(url, headers=headers, allow_redirects=self.config['scanning']['follow_redirects']) as resp:
                        return resp
                else:
                    async with self.session.request(method, url, data=data, headers=headers) as resp:
                        return resp
                        
            except aiohttp.ClientResponseError as e:
                if e.status == 429:
                    wait_time = (2 ** attempt) + (hash(url) % 5)
                    print(f"[!] Rate limited on {url}. Waiting {wait_time}s...")
                    await asyncio.sleep(wait_time)
                elif e.status >= 500:
                    await asyncio.sleep(1)
                    if attempt == max_retries - 1:
                        raise
                else:
                    raise
            except (aiohttp.ClientOSError, asyncio.TimeoutError):
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(1)

    async def run(self):
        """Main execution pipeline"""
        await self.init_session()
        
        try:
            urls = self.load_urls()
            print(f"[*] Loaded {len(urls)} target URLs")
            print(f"[*] Starting unified scan with all 16 modules...\n")
            
            # Step 1: Discover endpoints
            all_endpoints = []
            for url in urls:
                endpoints = await self.discover_endpoints(url)
                all_endpoints.extend(endpoints)
            
            print(f"[*] Discovered {len(all_endpoints)} endpoints total")
            
            # Step 2: Intelligence analysis
            print("[*] Running intelligence analysis...")
            intelligent_endpoints = []
            for endpoint in all_endpoints:
                analyzed = await self.analyze_endpoint_intelligence(endpoint)
                if analyzed:
                    intelligent_endpoints.append(analyzed)
            
            if not intelligent_endpoints:
                print("[!] No endpoints could be analyzed. Exiting.")
                return
            
            # Step 3: Prioritization
            print("[*] Prioritizing targets...")
            ep_list = []
            for ep in intelligent_endpoints:
                ep_list.append({
                    'endpoint': ep['url'],
                    'param_count': len(ep.get('parameters', [])),
                    'is_authenticated_only': ep.get('auth_required', False),
                    'method': 'GET',
                    'sensitivity_level': ep.get('sensitivity', 'public'),
                    'security_controls': []
                })
            
            prioritized_results = self.prioritization_engine.prioritize_endpoints(ep_list)
            
            prioritized = []
            for endpoint_url, priority_score, rank in prioritized_results:
                for ep in intelligent_endpoints:
                    if ep['url'] == endpoint_url:
                        ep['priority_score'] = priority_score
                        ep['attack_rank'] = rank
                        prioritized.append(ep)
                        break
            
            # Step 4: Register for cross-endpoint analysis
            print("[*] Registering endpoints for chain detection...")
            for endpoint in prioritized:
                self.cross_endpoint_analyzer.register_endpoint(
                    endpoint.get('url', ''),
                    endpoint.get('parameters', []),
                    endpoint.get('endpoint_type', 'unknown')
                )
            
            # Step 5: Scan each endpoint
            print("[*] Beginning targeted scans...\n")
            sem = asyncio.Semaphore(self.config['scanning']['concurrent_requests'])
            
            async def bounded_scan(endpoint_info):
                async with sem:
                    await self.scan_endpoint(endpoint_info)
            
            await asyncio.gather(*[bounded_scan(ep) for ep in prioritized])
            
            # Step 6: Cross-endpoint chains
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
            self.save_json()  # NEW: JSON export
            self.print_stats()

    async def discover_endpoints(self, base_url: str) -> List[str]:
        """Discover all accessible endpoints"""
        endpoints = [base_url]
        visited = {base_url}
        queue = [base_url]
        max_depth = self.config['targets'].get('max_depth', 2)
        current_depth = 0
        
        while queue and current_depth < max_depth:
            current_depth += 1
            next_queue = []
            
            for current_url in queue:
                try:
                    resp = await self.fetch_with_retry(current_url)
                    if not resp:
                        continue
                        
                    if resp.status < 400:
                        content_type = resp.headers.get('Content-Type', '')
                        if 'text/html' in content_type:
                            text = await resp.text()
                            
                            for match in re.finditer(r'href=["\']([^"\'?]+)', text):
                                link = match.group(1)
                                full_url = urljoin(current_url, link)
                                parsed_base = urlparse(base_url)
                                parsed_full = urlparse(full_url)
                                
                                if parsed_full.netloc == parsed_base.netloc:
                                    full_url = full_url.split('#')[0]
                                    if full_url not in visited and len(visited) < self.config['targets'].get('max_urls', 100):
                                        visited.add(full_url)
                                        endpoints.append(full_url)
                                        next_queue.append(full_url)
                except Exception as e:
                    continue
            
            queue = next_queue
        
        return endpoints

    async def analyze_endpoint_intelligence(self, endpoint_url: str) -> Optional[Dict]:
        """Module 8 + 9: Endpoint and parameter analysis"""
        endpoint_info = {
            'url': endpoint_url,
            'parameters': [],
            'endpoint_type': 'unknown',
            'risk_score': 0.0,
            'sensitivity': 'public',
            'auth_required': False
        }
        
        try:
            resp = await self.fetch_with_retry(endpoint_url, max_retries=2)
            if not resp:
                return endpoint_info
            
            text = await resp.text() if resp.status < 400 else ""
            
            # Module 8: Analyze endpoint
            analysis = self.endpoint_intelligence.analyze_endpoint(endpoint_url, 'GET', dict(resp.headers))
            endpoint_info['endpoint_type'] = analysis.get('endpoint_type', 'unknown')
            endpoint_info['risk_score'] = analysis.get('risk_score', 0.0)
            endpoint_info['sensitivity'] = analysis.get('sensitivity_level', 'public')
            endpoint_info['auth_required'] = analysis.get('auth_required', False)
            
            # Extract parameters from URL
            parsed = urlparse(endpoint_url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []
            path_params = re.findall(r'\{(\w+)\}', parsed.path)
            params.extend(path_params)
            
            # FIXED: Better default parameters if none found
            if not params:
                params = ['id', 'q', 'search', 'user', 'page', 'cat', 'item']
            
            endpoint_info['parameters'] = list(set(params))
            
            # Module 9: Analyze parameters
            if endpoint_info['parameters']:
                param_analysis = self.parameter_analyzer.analyze_parameters_batch(
                    endpoint_info['parameters'],
                    endpoint_url
                )
                endpoint_info['param_analysis'] = param_analysis
                max_param_score = max([p.get('attack_surface_score', 0) for p in param_analysis], default=0)
                endpoint_info['risk_score'] = max(endpoint_info['risk_score'], max_param_score)
            
            endpoint_info['has_waf'] = analysis.get('has_waf', False)
            
            return endpoint_info
            
        except Exception as e:
            return endpoint_info

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _jaccard_similarity(self, text1: str, text2: str) -> float:
        """Calculate Jaccard similarity"""
        if not text1 or not text2:
            return 0.0
        
        set1 = set(text1.split())
        set2 = set(text2.split())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0

    def _calculate_anomaly_score(self, similarity: float, time_anomaly: bool, 
                                  error_detected: bool, waf_detected: bool,
                                  status_code: int, payload_reflected: bool) -> float:
        """Calculate composite anomaly score (0-1)"""
        score = 0.0
        
        # Similarity anomaly (low similarity = high anomaly)
        score += (1 - similarity) * 0.3
        
        # Time anomaly
        if time_anomaly:
            score += 0.2
        
        # Error detected
        if error_detected:
            score += 0.25
        
        # WAF triggered (interesting even if blocked)
        if waf_detected:
            score += 0.15
        
        # Status code anomaly
        if status_code >= 500:
            score += 0.2
        elif status_code == 403 or status_code == 406:
            score += 0.15
        
        # Payload reflection
        if payload_reflected:
            score += 0.1
        
        return min(score, 1.0)

    def _detect_waf_heuristic(self, response_text: str, response_headers: Dict) -> bool:
        """Detect WAF presence"""
        waf_signatures = [
            'waf', 'cloudflare', 'akamai', 'imperva', 'sucuri',
            'mod_security', 'blocked', 'access denied', 'forbidden',
            'security check', 'captcha', 'challenge'
        ]
        
        text_lower = response_text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        server_header = headers_lower.get('server', '')
        if any(sig in server_header for sig in waf_signatures):
            return True
        
        if any(sig in text_lower for sig in waf_signatures):
            return True
        
        return False

    async def scan_endpoint(self, endpoint_info: Dict):
        """Full scan pipeline - FIXED to save ALL results"""
        url = endpoint_info.get('url', '')
        if not url:
            return
        
        endpoint_type = endpoint_info.get('endpoint_type', 'unknown')
        params = endpoint_info.get('parameters', [])
        
        # FIXED: Better parameter defaults
        if not params:
            params = ['id', 'q', 'search', 'user', 'page']
        
        # Get strategy
        strategy = self.strategy_layer.select_strategy_for_endpoint(
            url, endpoint_type, 
            endpoint_info.get('param_analysis', []),
            detected_attacks=[]
        )
        
        depth = strategy.get('depth', 2)
        strategy_name = strategy.get('strategy_name', 'unknown')
        self.strategy_history.append(strategy_name)
        
        print(f"[SCAN] {url} (Priority: {endpoint_info.get('priority_score', 0):.1f})")
        
        # Get baseline
        baseline = None
        baseline_resp = await self.fetch_with_retry(url, max_retries=1)
        if baseline_resp and baseline_resp.status < 400:
            try:
                baseline = await baseline_resp.text()
            except:
                baseline = ""
        
        attempt_count = 0
        signals_found = 0
        max_attempts = min(20, self.config['scanning'].get('max_attempts_per_endpoint', 20))
        scan_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]
        
        # Test parameters
        for param in params:
            if attempt_count >= max_attempts:
                break
            
            for payload_type in self.config['payloads'].keys():
                if attempt_count >= max_attempts:
                    break
                
                payloads = self.config['payloads'][payload_type][:3]
                
                for payload_idx, payload in enumerate(payloads):
                    if attempt_count >= max_attempts:
                        break
                    
                    # Module 7: Failure simulation
                    failure_result = self.realistic_failure_simulator.simulate_attack_attempt(
                        url, payload, 'medium'
                    )
                    
                    if failure_result.get('failure_occurred'):
                        # FIXED: Still save the failed attempt for ML
                        fail_record = {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'payload_type': payload_type,
                            'label': 0,  # Not vulnerable
                            'failure_simulated': True,
                            'failure_mode': failure_result.get('failure_mode'),
                            'timestamp': datetime.now().isoformat()
                        }
                        self.results.append(fail_record)
                        self.stats['saved'] += 1
                        
                        attempt_count += 1
                        await asyncio.sleep(self.config['scanning']['delay'])
                        continue
                    
                    # Module 11: Smart payload selection
                    try:
                        selected_payloads = self.smart_payload_selector.select_payloads(
                            endpoint_type=endpoint_type,
                            param_type=self.parameter_analyzer._classify_parameter_type(param, url),
                            attack_surface_score=endpoint_info.get('risk_score', 5),
                            available_payloads=self.config['payloads']
                        )
                        
                        if selected_payloads and payload_idx == 0:
                            payload = selected_payloads[0].get('payload', payload)
                    except Exception as e:
                        pass
                    
                    # Module 13: Payload mutation
                    try:
                        mutations = self.mutation_engine.generate_mutations(payload, mutation_count=3)
                        if mutations:
                            mutated_payload = mutations[0]['payload']
                            mutation_type = mutations[0]['mutation_type']
                        else:
                            mutated_payload = payload
                            mutation_type = 'original'
                    except Exception as e:
                        mutated_payload = payload
                        mutation_type = 'original'
                    
                    # Test payload
                    start_time = time.time()
                    result = await self.test_payload(
                        url, param, mutated_payload, payload_type, 
                        baseline, endpoint_info, mutation_type
                    )
                    elapsed = time.time() - start_time
                    
                    # FIXED: ALWAYS save result, regardless of vulnerability
                    if result:
                        # Calculate execution signals
                        execution_signals = []
                        if result.get('is_vulnerable'):
                            execution_signals.append("vulnerability_detected")
                        if result.get('payload_reflected'):
                            execution_signals.append("payload_reflected")
                        if result.get('error_detected'):
                            execution_signals.append("error_revealed")
                        if result.get('time_anomaly'):
                            execution_signals.append("time_anomaly")
                        if result.get('waf_detected'):
                            execution_signals.append("waf_triggered")
                        
                        # Module 16: Attack chain
                        chain_result = self.attack_chain_engine.track_attack(
                            scan_id, url, payload_type, mutated_payload,
                            result.get('is_vulnerable', False),
                            execution_signals, elapsed
                        )
                        
                        # Module 1: Pattern learning
                        if result.get('is_vulnerable'):
                            self.pattern_learning.record_successful_attack(
                                param, 
                                self.parameter_analyzer._classify_parameter_type(param, url),
                                payload_type, 
                                mutated_payload,
                                url, 
                                {'method': 'GET', 'auth_level': 'guest', 'strategy': strategy_name}
                            )
                        else:
                            self.pattern_learning.record_failed_attack(
                                param,
                                self.parameter_analyzer._classify_parameter_type(param, url),
                                payload_type,
                                mutated_payload
                            )
                        
                        # FIXED: Build complete record with label
                        full_result = {
                            **result,
                            'scan_id': scan_id,
                            'priority_score': endpoint_info.get('priority_score', 0),
                            'attack_rank': endpoint_info.get('attack_rank', 0),
                            'strategy_name': strategy_name,
                            'attempt_count': attempt_count,
                            'mutation_type': mutation_type,
                            'failure_simulated': False,
                            'chain_depth': chain_result.get('chain_depth', 0),
                            'chain_success': chain_result.get('chain_success', False),
                            'execution_signals': ','.join(execution_signals),
                        }
                        
                        # CRITICAL FIX: Always append, not just if vulnerable
                        self.results.append(full_result)
                        self.stats['saved'] += 1
                        
                        if result.get('is_vulnerable'):
                            signals_found += 1
                            self.stats['vulns'] += 1
                            print(f"  [!] VULNERABLE: {payload_type} on {param} (anomaly: {result.get('anomaly_score', 0):.2f})")
                    
                    # Module 6: Stop condition
                    should_stop, reason, analysis = self.stop_condition_evaluator.should_stop_attacking(
                        url, 
                        attempt_count, 
                        signals_found,
                        waf_blocks=self.stats['waf_triggers'],
                        response_codes=[result.get('status_code', 200)] if result else []
                    )
                    
                    if should_stop:
                        print(f"  [STOP] {reason}")
                        break
                    
                    attempt_count += 1
                    await asyncio.sleep(self.config['scanning']['delay'])
        
        # Module 4: Impact simulation
        if signals_found > 0:
            try:
                impact = self.impact_simulator.simulate_impact(
                    attack_type='idor',
                    endpoint=url,
                    endpoint_type=endpoint_type,
                    affected_users=10,
                    data_sensitivity=endpoint_info.get('sensitivity', 'public'),
                    is_authenticated=endpoint_info.get('auth_required', False)
                )
                
                if impact.get('bounty_worthy'):
                    print(f"    [IMPACT] Bounty-worthy: {impact.get('severity', 'unknown')}")
            except Exception as e:
                pass

    async def test_payload(self, url: str, param: str, payload: str, 
                          payload_type: str, baseline: Optional[str],
                          endpoint_info: Dict, mutation_type: str) -> Optional[Dict]:
        """Test single payload with ENHANCED detection"""
        try:
            # Construct request
            parsed = urlparse(url)
            if '?' in url:
                test_url = f"{url}&{param}={quote(payload)}"
            else:
                test_url = f"{url}?{param}={quote(payload)}"
            
            start = time.time()
            resp = await self.fetch_with_retry(test_url, max_retries=2)
            
            if not resp:
                return None
            
            response_text = await resp.text()
            elapsed = time.time() - start
            
            self.stats['requests'] += 1
            
            # FIXED: Enhanced detection logic
            is_vulnerable = False
            error_detected = False
            payload_reflected = payload in response_text
            
            # 1. Reflection-based detection
            if payload_reflected:
                is_vulnerable = True
            
            # 2. Error pattern detection (all patterns, not just payload_type)
            patterns = self.config['detection']['error_patterns']
            for ptype, pattern in patterns.items():
                if re.search(pattern, response_text, re.IGNORECASE):
                    is_vulnerable = True
                    error_detected = True
                    break
            
            # 3. Similarity anomaly detection
            similarity = self._jaccard_similarity(baseline, response_text) if baseline else 0.5
            if similarity < 0.7:  # Response changed significantly
                is_vulnerable = True
            
            # 4. Time-based detection
            time_anomaly = elapsed > self.config['detection']['slow_threshold']
            if time_anomaly:
                is_vulnerable = True
            
            # 5. Status code anomaly
            status_anomaly = resp.status >= 500 or resp.status in [403, 406]
            if status_anomaly:
                is_vulnerable = True
            
            # 6. WAF detection
            waf_detected = self._detect_waf_heuristic(response_text, dict(resp.headers))
            if waf_detected:
                self.stats['waf_triggers'] += 1
            
            # FIXED: Calculate proper anomaly_score
            anomaly_score = self._calculate_anomaly_score(
                similarity, time_anomaly, error_detected, 
                waf_detected, resp.status, payload_reflected
            )
            
            # Build comprehensive result
            result = {
                'url': url,
                'parameter': param,
                'payload': payload,
                'payload_type': payload_type,
                'mutation_type': mutation_type,
                'label': 1 if is_vulnerable else 0,  # EXPLICIT LABEL
                'is_vulnerable': is_vulnerable,
                'payload_reflected': payload_reflected,
                'error_detected': error_detected,
                'similarity_to_baseline': round(similarity, 3),
                'anomaly_score': round(anomaly_score, 3),  # FIXED: Now calculated
                'time_anomaly': time_anomaly,
                'status_code': resp.status,
                'response_time': round(elapsed, 3),
                'response_size': len(response_text),
                'entropy': round(self._calculate_entropy(response_text), 3),
                'waf_detected': waf_detected,
                'has_auth': endpoint_info.get('auth_required', False),
                'endpoint_type': endpoint_info.get('endpoint_type', 'unknown'),
                'risk_score': endpoint_info.get('risk_score', 0),
                'timestamp': datetime.now().isoformat(),
            }
            
            return result
            
        except Exception as e:
            self.stats['errors'] += 1
            return None

    def save_csv(self):
        """Save results to CSV"""
        if not self.results:
            print("[!] No results to save")
            return
        
        output_file = self.config['output']['csv_file']
        
        # Ensure all records have same fields
        all_keys = set()
        for result in self.results:
            all_keys.update(result.keys())
        
        # Add missing keys with defaults
        final_results = []
        for result in self.results:
            record = {}
            for key in all_keys:
                record[key] = result.get(key, '')
            final_results.append(record)
        
        if final_results:
            fieldnames = sorted(list(final_results[0].keys()))
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(final_results)
            
            print(f"[OK] Saved {len(final_results)} records to {output_file}")

    def save_json(self):
        """NEW: Save results to JSON for better ML compatibility"""
        if not self.results:
            return
        
        json_file = self.config['output']['csv_file'].replace('.csv', '.json')
        
        # Add metadata
        export_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'scanner_version': '4.0-fixed',
                'total_records': len(self.results),
                'vulnerable_count': sum(1 for r in self.results if r.get('label') == 1),
                'clean_count': sum(1 for r in self.results if r.get('label') == 0),
                'configuration': {
                    'targets': self.config['targets']['urls'],
                    'payload_types': list(self.config['payloads'].keys())
                }
            },
            'records': self.results
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"[OK] Saved JSON export to {json_file}")

    def print_stats(self):
        """Print completion statistics"""
        print("\n" + "="*70)
        print("SCAN COMPLETE - v4.0 Unified Vulnerability Scanner (FIXED)")
        print("="*70)
        print(f"Total Requests: {self.stats['requests']}")
        print(f"Records Saved: {self.stats['saved']}")
        print(f"Vulnerabilities Found: {self.stats['vulns']}")
        print(f"WAF Triggers: {self.stats['waf_triggers']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"CSV Output: {self.config['output']['csv_file']}")
        print(f"JSON Output: {self.config['output']['csv_file'].replace('.csv', '.json')}")
        
        # Label distribution
        if self.results:
            vuln_count = sum(1 for r in self.results if r.get('label') == 1)
            clean_count = sum(1 for r in self.results if r.get('label') == 0)
            print(f"\nDataset Balance:")
            print(f"  Positive (vulnerable): {vuln_count}")
            print(f"  Negative (clean): {clean_count}")
            print(f"  Ratio: {vuln_count/max(clean_count, 1):.3f}")
        
        print("="*70)


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='AI Vulnerability Dataset Generator v4.0 - FIXED VERSION'
    )
    parser.add_argument('--config', type=str, default='../../config/config.json',
                        help='Path to config file')
    parser.add_argument('--url-file', type=str, default=None,
                        help='URL file (one per line)')
    parser.add_argument('--output-csv', type=str, default=None,
                        help='Output CSV path')
    parser.add_argument('--max-attempts', type=int, default=None,
                        help='Max attempts per endpoint')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config):
        print(f"[ERROR] Config not found: {args.config}")
        sys.exit(1)
    
    scanner = UnifiedVulnerabilityScanner(config_path=args.config)
    
    if args.url_file and os.path.exists(args.url_file):
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        scanner.config['targets']['urls'] = urls
        print(f"[*] Loaded {len(urls)} URLs from {args.url_file}\n")
    
    if args.output_csv:
        scanner.config['output']['csv_file'] = args.output_csv
    
    if args.max_attempts:
        scanner.config['scanning']['max_attempts_per_endpoint'] = args.max_attempts
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.save_csv()
        scanner.save_json()
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()