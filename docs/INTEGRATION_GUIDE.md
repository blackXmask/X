# INTEGRATION GUIDE - Add These Sections to data.py

## Step 1: Add Imports (After line 1-10 of current imports)

```python
# NEW: Intelligence engines for human-like bug bounty simulation
from src.dataset.endpoint_intelligence import EndpointIntelligence
from src.dataset.parameter_analyzer import ParameterAnalyzer
from src.dataset.auth_context_handler import AuthContextHandler
from src.dataset.smart_payload_selector import SmartPayloadSelector
from src.dataset.attack_chain import EnhancedAttackChainEngine
```

---

## Step 2: Initialize in __init__ (After line 65 - after existing engine initialization)

```python
# Priority 1.5: Endpoint intelligence
self.endpoint_intelligence = EndpointIntelligence()

# Priority 1.6: Parameter analysis
self.parameter_analyzer = ParameterAnalyzer()

# Priority 2: Multi-level authentication
self.auth_handler = AuthContextHandler()

# Priority 3: Smart payload selection
self.payload_selector = SmartPayloadSelector()

# Priority 5: Enhanced attack chain with behavioral tracking
self.attack_chain_engine = EnhancedAttackChainEngine()
```

---

## Step 3: New Method - Analyze Endpoint (Add to VulnerabilityDataCollector class)

```python
def _analyze_endpoint_context(self, url: str, method: str) -> Dict:
    """
    Priority 1.5: Analyze endpoint for intelligent targeting.
    """
    endpoint_analysis = self.endpoint_intelligence.analyze_endpoint(
        url, 
        method, 
        self.session.headers if hasattr(self, 'session') else {}
    )
    return endpoint_analysis
```

---

## Step 4: New Method - Select Payloads Smartly (Add to class)

```python
def _select_smart_payloads(
    self, 
    endpoint_type: str,
    param_type: str,
    attack_surface: int
) -> List[Dict]:
    """
    Priority 3: Select payloads based on endpoint and parameter context.
    """
    payloads = self.payload_selector.select_payloads(
        endpoint_type,
        param_type,
        attack_surface
    )
    return payloads
```

---

## Step 5: Enhanced test_payload() - Key Changes

Replace the main payload testing loop with this structure:

```python
async def test_payload_enhanced(self, url: str, method: str = 'GET', **kwargs):
    """
    NEW WORKFLOW: Human-like bug bounty approach
    """
    # STEP 1: Understand endpoint
    endpoint_context = self._analyze_endpoint_context(url, method)
    
    if endpoint_context['endpoint_type'] == 'static':
        return  # Skip static files
    
    # STEP 2: Analyze parameters
    parameters = self._extract_form_params(url)
    param_analysis = self.parameter_analyzer.analyze_parameters_batch(
        parameters, 
        url
    )
    priority_params = param_analysis[:3]  # Top 3 parameters
    
    # STEP 3: Setup authentication variants
    auth_variants = self.auth_handler.get_all_auth_variants()
    test_endpoints, test_auth_levels = \
        self.payload_selector.should_test_endpoint_with_auth(
            endpoint_context['endpoint_type'],
            endpoint_context['auth_required']
        )
    
    # STEP 4-8: For each parameter x auth variant x attack type
    for param in priority_params:
        # Select context-aware payloads
        smart_payloads = self._select_smart_payloads(
            endpoint_context['endpoint_type'],
            param['param_type'],
            param['attack_surface_score']
        )
        
        for payload_spec in smart_payloads:
            attack_type = payload_spec['attack_type']
            fallback_strategy = payload_spec['fallback_strategy']
            
            # Test with different auth contexts
            for auth_level in test_auth_levels:
                auth_context = {
                    'guest': self.auth_handler.get_guest_context(),
                    'user': self.auth_handler.get_user_context(),
                    'admin': self.auth_handler.get_admin_context(),
                }.get(auth_level)
                
                # Attempt counter for this param/attack combo
                attempt = 0
                max_attempts = 5
                
                # Adaptive attack loop with decision making
                while attempt < max_attempts:
                    attempt += 1
                    
                    # Get payloads for this attack type
                    payloads = self.config['payloads'].get(
                        attack_type.replace('injection', 'sqli'),
                        ['<test>']
                    )
                    
                    for payload in payloads[:2]:  # Try top 2
                        # Send request
                        result = await self._test_single_payload(
                            url, 
                            method, 
                            param['param_name'],
                            payload,
                            auth_context
                        )
                        
                        # Extract execution signals
                        execution_signals = self._detect_execution_signal(
                            result['response'],
                            payload,
                            attack_type
                        )
                        
                        # Track attack chain (Priority 5)
                        chain_result = self.attack_chain_engine.track_attack(
                            scan_id=self.scan_id,
                            target_url=url,
                            payload_type=attack_type,
                            payload=payload,
                            exploit_success=bool(execution_signals),
                            execution_signals=execution_signals,
                            response_time=result.get('response_time', 0),
                            response_size=result.get('response_size', 0),
                            discovery_source='crawl'  # Priority 6
                        )
                        
                        # Adaptive decision making (Priority 4)
                        next_action = self.payload_selector.decide_next_action(
                            {
                                'reflected': result.get('reflected', False),
                                'error': result.get('error_detected', False),
                                'timeout': result.get('timeout', False),
                                'blocked': result.get('blocked', False),
                                'status_changed': result.get('status_changed', False),
                            },
                            attempt,
                            max_attempts
                        )
                        
                        # REAL EXPLOITABILITY LABELING (Priority 4)
                        label_data = self.labeling_engine.generate_label(
                            vulnerability_detected=result.get('vulnerability_detected', False),
                            exploit_confirmed=bool(execution_signals),
                            confidence_score=result.get('confidence_score', 0),
                            execution_signals=execution_signals,
                            reflection_present=result.get('reflected', False),
                            anomaly_score=result.get('anomaly_score', 0),
                            payload_type=attack_type,
                            # NEW PARAMETERS for real exploitability:
                            endpoint_type=endpoint_context['endpoint_type'],
                            sensitivity_level=endpoint_context['sensitivity_level'],
                            auth_required=endpoint_context['auth_required']
                        )
                        
                        # Build comprehensive record
                        record = {
                            # Priority 1.5: Endpoint intelligence
                            'endpoint_type': endpoint_context['endpoint_type'],
                            'endpoint_risk_score': endpoint_context['risk_score'],
                            'endpoint_sensitivity': endpoint_context['sensitivity_level'],
                            
                            # Priority 1.6: Parameter intelligence
                            'param_name': param['param_name'],
                            'param_type': param['param_type'],
                            'param_attack_surface': param['attack_surface_score'],
                            'param_recommended_attacks': ','.join(param['recommended_attacks']),
                            
                            # Priority 2: Authentication
                            'auth_context': auth_context['role'],
                            'tested_with_auth': auth_context['is_authenticated'],
                            
                            # Priority 3: Smart payload selection
                            'payload_strategy': 'context-aware',
                            'mutation_strategy': fallback_strategy,
                            
                            # Priority 4: Real exploitability
                            'label': label_data['label'],
                            'real_vulnerability': label_data['real_vulnerability'],
                            'bug_bounty_valid': label_data['bug_bounty_valid'],
                            'false_positive': label_data['false_positive'],
                            'false_positive_reason': label_data.get('false_positive_reason', ''),
                            'exploit_type': label_data['exploit_type'],
                            'impact': label_data['impact'],
                            'is_exploitable': label_data['exploitable'],
                            
                            # Priority 5: Attack chain
                            'chain_id': chain_result['chain_id'],
                            'attack_stage': chain_result['attack_stage'],
                            'chain_depth': chain_result['chain_depth'],
                            'chain_success_rate': chain_result['success_rate'],
                            'successful_stages': ','.join(chain_result['successful_stages']),
                            'compromise_confidence': chain_result['compromise_confidence'],
                            'strategy_shifts': chain_result['strategy_shifts'],
                            
                            # Priority 6: Discovery tracking
                            'discovery_source': 'crawl',
                            
                            # Priority 7: Behavioral features
                            'decision_path': chain_result['decision_path'],
                            'attempt_count': chain_result['attempt_count'],
                            'escalation_depth': chain_result['attempt_count'],
                            
                            # Original fields (keep existing)
                            'scan_id': self.scan_id,
                            'timestamp': result.get('timestamp', ''),
                            'target_url': url,
                            'payload': payload,
                            'payload_type': attack_type,
                            'response_status': result.get('response_status', ''),
                            'response_time_ms': result.get('response_time', 0),
                            'response_size_bytes': result.get('response_size', 0),
                            'vulnerability_detected': result.get('vulnerability_detected', False),
                            'confidence_score': result.get('confidence_score', 0),
                            'anomaly_score': result.get('anomaly_score', 0),
                            'reflected': result.get('reflected', False),
                            'error_detected': result.get('error_detected', False),
                            'blocked': result.get('blocked', False),
                        }
                        
                        self.records.append(record)
                        
                        # Decide next action
                        if next_action == 'stop':
                            break
                    
                    if next_action == 'switch':
                        break  # Try next attack type
```

---

## Step 6: Update save_csv() - Add New Fields

Add these field names to the CSV header:

```python
def save_csv(self):
    """Save records to CSV with NEW fields."""
    
    field_names = [
        # Existing fields
        'scan_id', 'timestamp', 'target_url', 'payload', 'payload_type',
        'response_status', 'response_time_ms', 'response_size_bytes',
        'vulnerability_detected', 'confidence_score', 'anomaly_score',
        'reflected', 'error_detected', 'blocked',
        
        # NEW Priority 1.5: Endpoint intelligence
        'endpoint_type', 'endpoint_risk_score', 'endpoint_sensitivity',
        
        # NEW Priority 1.6: Parameter intelligence
        'param_name', 'param_type', 'param_attack_surface',
        'param_recommended_attacks',
        
        # NEW Priority 2: Authentication
        'auth_context', 'tested_with_auth',
        
        # NEW Priority 3: Smart payloads
        'payload_strategy', 'mutation_strategy',
        
        # NEW Priority 4: Real exploitability (MOST IMPORTANT)
        'label',                  # 0 or 1 - THE LABEL
        'real_vulnerability',     # Is it REAL?
        'bug_bounty_valid',      # Worth reporting?
        'false_positive',         # False alarm?
        'false_positive_reason',  # Why?
        'exploit_type', 'impact', 'is_exploitable',
        
        # NEW Priority 5: Attack chains
        'chain_id', 'attack_stage', 'chain_depth',
        'chain_success_rate', 'successful_stages',
        'compromise_confidence', 'strategy_shifts',
        
        # NEW Priority 6: Discovery tracking
        'discovery_source',
        
        # NEW Priority 7: Behavioral features
        'decision_path', 'attempt_count', 'escalation_depth',
    ]
    
    with open(self.config.get('output', {}).get('csv_file', 'output.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        writer.writeheader()
        writer.writerows(self.records)
```

---

## Summary of Integration

| Section | What to Add | Where |
|---------|-----------|-------|
| 1 | 5 new imports | Top of file |
| 2 | 5 engine initializations | __init__ method |
| 3 | 2 new helper methods | VulnerabilityDataCollector class |
| 4 | Enhanced test_payload() | Replace existing loop |
| 5 | Updated CSV export | save_csv() method |

---

## Testing After Integration

```bash
python src/dataset/data.py --config config/config.json
```

Check output CSV for:
- ✅ All new fields present
- ✅ Labels are 0 or 1 (binary)
- ✅ real_vulnerability is True/False
- ✅ bug_bounty_valid is True/False
- ✅ decision_path shows attack sequence
- ✅ chain_depth > 0 for successful chains
