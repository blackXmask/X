"""
Smart Payload Selector - Select payloads based on endpoint and parameter intelligence.

Priority 3: Intelligent Payload Selection
- Contextual payload selection based on endpoint type and parameter classification
- Adaptive strategy: mutate → escalate → switch
- Decision tree for attack type selection
"""

from typing import Dict, List, Optional


class SmartPayloadSelector:
    """Select smart payloads based on endpoint and parameter context."""
    
    def __init__(self):
        """Initialize attack strategy mapping."""
        # Map endpoint/parameter to attack priority order
        self.attack_strategy_map = {
            ('api', 'query'): ['sqli', 'json_injection', 'xss'],
            ('api', 'id'): ['sqli', 'idor', 'enumeration'],
            ('api', 'generic'): ['xss', 'sqli'],
            
            ('login', 'query'): ['sqli', 'xss'],
            ('login', 'generic'): ['sqli', 'brute_force'],
            
            ('search', 'query'): ['xss', 'sqli'],
            ('search', 'generic'): ['xss', 'sqli'],
            
            ('upload', 'file'): ['file_upload', 'xxe'],
            ('upload', 'generic'): ['file_upload'],
            
            ('admin', 'id'): ['sqli', 'bypass', 'idor'],
            ('admin', 'generic'): ['xss', 'sqli', 'bypass'],
            
            ('dashboard', 'generic'): ['xss', 'csrf'],
            ('config', 'generic'): ['directory_traversal', 'file_read'],
            
            ('other', 'id'): ['idor', 'sqli'],
            ('other', 'query'): ['xss', 'sqli'],
            ('other', 'generic'): ['xss', 'sqli'],
        }
    
    def select_payloads(
        self,
        endpoint_type: str,
        param_type: str,
        attack_surface_score: int = 5,
        available_payloads: Dict[str, List[str]] = None
    ) -> List[Dict]:
        """
        Select best payloads for endpoint/parameter combination.
        
        Args:
            endpoint_type: Type of endpoint (api, login, search, etc.)
            param_type: Type of parameter (id, query, file, etc.)
            attack_surface_score: Priority score (0-10)
            available_payloads: Dict mapping attack types to payload lists
        
        Returns:
            List of payload selections sorted by priority
        """
        # Get attack priority order for this combination
        key = (endpoint_type, param_type)
        attack_types = self.attack_strategy_map.get(key)
        
        if not attack_types:
            # Fallback to generic strategy
            attack_types = self.attack_strategy_map.get((endpoint_type, 'generic'), ['xss', 'sqli'])
        
        # Adjust strategy based on difficulty
        if attack_surface_score <= 3:
            # Low surface = only try easy attacks
            attack_types = attack_types[:1]
        elif attack_surface_score <= 6:
            # Medium surface = try top 2 attacks
            attack_types = attack_types[:2]
        
        return [
            {
                'attack_type': attack_type,
                'priority': idx,
                'fallback_strategy': self._get_fallback_strategy(idx),
            }
            for idx, attack_type in enumerate(attack_types)
        ]
    
    def decide_next_action(
        self,
        last_result: Dict,
        attempt_count: int = 1,
        max_attempts: int = 5
    ) -> str:
        """
        Adaptive decision making: what to do after a test result.
        
        Result format:
            {
                'reflected': bool,
                'error': bool,
                'timeout': bool,
                'blocked': bool,
                'status_changed': bool,
                'payload_complexity': int (0-100)
            }
        
        Returns:
            'mutate' / 'escalate' / 'switch' / 'stop'
        """
        # If payload was reflected, try encoding
        if last_result.get('reflected') and not last_result.get('blocked'):
            return 'mutate'
        
        # If error detected, payload might work - escalate
        if last_result.get('error') and attempt_count < max_attempts:
            return 'escalate'
        
        # If blocked, try other mutation
        if last_result.get('blocked'):
            return 'mutate'
        
        # If timeout, try different attack
        if last_result.get('timeout'):
            return 'switch'
        
        # If status changed, continue current approach
        if last_result.get('status_changed'):
            return 'mutate'
        
        # Reached attempt limit, switch
        if attempt_count >= max_attempts:
            return 'switch'
        
        # Default: try a mutation
        return 'mutate'
    
    def _get_fallback_strategy(self, attempt_number: int) -> str:
        """Get fallback strategy for when primary attack doesn't work."""
        strategies = [
            'mutate_encoding',      # 0: Try URL encoding
            'mutate_comments',       # 1: Try comment injection
            'escalate_complexity',   # 2: Increase payload size
            'switch_approach',       # 3: Try different attack type
            'adaptive_learn',        # 4: Learn from responses
        ]
        
        if attempt_number < len(strategies):
            return strategies[attempt_number]
        
        return 'stop'
    
    def prioritize_attacks_by_impact(
        self,
        endpoint_type: str,
        sensitivity_level: str
    ) -> List[str]:
        """
        Prioritize attack types by potential impact.
        
        Critical endpoints get high-impact attacks first.
        """
        impact_priority = {
            'config': ['file_read', 'directory_traversal', 'xxe'],
            'payment': ['sqli', 'idor', 'bypass'],
            'user_data': ['idor', 'xss', 'sqli'],
            'unknown': ['xss', 'sqli'],
            'public': ['xss'],
        }
        
        return impact_priority.get(sensitivity_level, ['xss', 'sqli'])
    
    def get_mutation_sequence_for_attack(self, attack_type: str) -> List[str]:
        """
        Get mutation sequence for an attack type before switching attacks.
        
        Represents "escalation within one attack type".
        """
        sequences = {
            'xss': [
                'none',                 # Raw payload
                'html_encode',          # &lt; &gt; etc
                'unicode_encode',       # \\u format
                'mixed_case',           # MiXeD CaSe
                'comment_injection',    # /* comment */ payload
                'double_encode',        # %2527 etc
            ],
            
            'sqli': [
                'none',                 # Raw payload
                'space_replace',        # /**/ or %20
                'comment_bypass',       # -- or #
                'case_variation',       # SeLeCt vs select
                'encoding',             # hex or char encoding
                'buffer_overflow',      # Long payload
            ],
            
            'file_upload': [
                'none',                 # Raw file
                'polyglot',             # Valid multiple types
                'null_byte',            # Filename with \\x00
                'double_ext',           # .php.jpg
                'modify_headers',       # Wrong Content-Type
            ],
        }
        
        return sequences.get(attack_type, [
            'none',
            'encoding',
            'mutation',
            'escalation',
        ])
    
    def should_test_with_auth_variant(
        self,
        endpoint_type: str,
        param_type: str
    ) -> bool:
        """Determine if this endpoint/param should be tested with different auth levels."""
        # IDOR attacks need different users
        if param_type in ['id', 'user_id']:
            return True
        
        # Admin endpoints worth testing with user context
        if endpoint_type in ['admin', 'dashboard']:
            return True
        
        # User data endpoints worth testing across contexts
        if endpoint_type in ['profile', 'account', 'user']:
            return True
        
        return False
