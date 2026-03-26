"""
Pattern Learning Layer - Memory Across Scans

Enables the scanner to learn from previous successful attacks and recognize
patterns across different targets. This transforms isolated scans into a learning
system that becomes smarter with each vulnerability discovery.

Key Features:
- Track successful payloads across scans
- Store parameter→attack patterns (e.g., "param=id → usually IDOR")
- Calculate success rates for each pattern
- Provide intelligent suggestions for future scans
- Cross-target learning (what worked on Site A might work on Site B)

Real-world use:
- Site 1: /user?id=123 → IDOR found
- Site 2: /profile?id=456 → Scanner remembers pattern_id→idor, tries it first
"""

from typing import Dict, List, Tuple, Any
from datetime import datetime
import json


class PatternLearningEngine:
    """
    Machine learning layer that remembers patterns across multiple scans.
    
    Attributes:
        learned_patterns: Dict mapping pattern names to their metrics
        successful_payloads_history: List of payloads that successfully exploited vulnerabilities
        scan_memory: Memory trace from previous scans
        pattern_success_rate: Tracks success rate for each pattern
    """
    
    def __init__(self):
        """Initialize the learning engine with empty memory."""
        # Pattern discovery: parameter_type → list of (attack_type, (success_count, failed_count))
        self.learned_patterns: Dict[str, Dict[str, Tuple[int, int]]] = {
            'id': {'idor': (0, 0), 'sqli': (0, 0), 'enumeration': (0, 0)},
            'query': {'xss': (0, 0), 'sqli': (0, 0)},
            'path': {'directory_traversal': (0, 0), 'path_normalization': (0, 0)},
            'file': {'file_upload': (0, 0), 'rce': (0, 0)},
            'token': {'token_prediction': (0, 0), 'token_replay': (0, 0)},
            'generic': {'reflective_xss': (0, 0), 'blindxss': (0, 0)},
        }
        
        # Successful payloads: payload → (attack_type, success_count)
        self.successful_payloads_history: Dict[str, Tuple[str, int]] = {}
        
        # Scan memory: stores context from previous scans
        self.scan_memory: List[Dict[str, Any]] = []
        
        # Pattern success rates: pattern_name → success_rate (0-1)
        self.pattern_success_rate: Dict[str, float] = {}
        
        # Common patterns discovered
        self.common_patterns = {
            'id_idor': {'attack_type': 'idor', 'success_rate': 0.0, 'count': 0},
            'query_xss': {'attack_type': 'xss', 'success_rate': 0.0, 'count': 0},
            'file_rce': {'attack_type': 'rce', 'success_rate': 0.0, 'count': 0},
            'jwt_manipulation': {'attack_type': 'auth_bypass', 'success_rate': 0.0, 'count': 0},
        }
    
    def record_successful_attack(self, param_name: str, param_type: str, 
                                 attack_type: str, payload: str, 
                                 endpoint: str, context: Dict[str, Any]) -> None:
        """
        Record a successful attack to learn from it.
        
        Args:
            param_name: Name of the vulnerable parameter (e.g., 'user_id')
            param_type: Type of parameter (id, query, file, token, etc.)
            attack_type: Type of attack that succeeded (idor, xss, sqli, etc.)
            payload: The actual payload that worked
            endpoint: The endpoint where this worked (e.g., '/api/users')
            context: Additional context (method, auth_level, etc.)
        """
        # Update pattern success count
        if param_type in self.learned_patterns:
            if attack_type in self.learned_patterns[param_type]:
                success, failed = self.learned_patterns[param_type][attack_type]
                self.learned_patterns[param_type][attack_type] = (success + 1, failed)
        
        # Store successful payload
        payload_key = f"{param_type}_{attack_type}"
        if payload_key in self.successful_payloads_history:
            attack, count = self.successful_payloads_history[payload_key]
            self.successful_payloads_history[payload_key] = (attack, count + 1)
        else:
            self.successful_payloads_history[payload_key] = (attack_type, 1)
        
        # Store in scan memory
        memory_entry = {
            'timestamp': datetime.now().isoformat(),
            'param_name': param_name,
            'param_type': param_type,
            'attack_type': attack_type,
            'payload': payload,
            'endpoint': endpoint,
            'context': context,
        }
        self.scan_memory.append(memory_entry)
        
        # Update common patterns if applicable
        pattern_key = f"{param_type}_{attack_type}"
        if pattern_key in self.common_patterns:
            self.common_patterns[pattern_key]['count'] += 1
            self._recalculate_success_rate(pattern_key)
    
    def record_failed_attack(self, param_name: str, param_type: str, 
                            attack_type: str, payload: str) -> None:
        """
        Record a failed attack attempt to refine success rates.
        
        Args:
            param_name: Name of the parameter
            param_type: Type of parameter
            attack_type: Type of attack attempted
            payload: The payload that failed
        """
        if param_type in self.learned_patterns:
            if attack_type in self.learned_patterns[param_type]:
                success, failed = self.learned_patterns[param_type][attack_type]
                self.learned_patterns[param_type][attack_type] = (success, failed + 1)
    
    def get_attack_priority_for_parameter(self, param_type: str, 
                                         param_name: str = '') -> List[Tuple[str, float]]:
        """
        Get recommended attacks for a parameter type, ranked by success rate.
        
        Returns list of (attack_type, success_rate) tuples sorted by success rate.
        
        Args:
            param_type: Type of parameter (id, query, file, etc.)
            param_name: Optional specific parameter name for pattern matching
            
        Returns:
            List of (attack_type, estimated_success_rate) tuples
        """
        if param_type not in self.learned_patterns:
            return []
        
        attacks_with_rates = []
        for attack_type, (success, failed) in self.learned_patterns[param_type].items():
            total = success + failed
            if total > 0:
                success_rate = success / total
            else:
                # No history: use prior probability (common pattern)
                success_rate = self._estimate_prior_probability(param_type, attack_type)
            
            attacks_with_rates.append((attack_type, success_rate))
        
        # Sort by success rate descending
        return sorted(attacks_with_rates, key=lambda x: x[1], reverse=True)
    
    def _estimate_prior_probability(self, param_type: str, attack_type: str) -> float:
        """
        Estimate prior probability for parameter/attack combo not yet seen.
        
        Uses domain knowledge about common vulnerabilities.
        """
        priors = {
            'id': {'idor': 0.65, 'sqli': 0.45, 'enumeration': 0.55},
            'query': {'xss': 0.70, 'sqli': 0.60},
            'file': {'file_upload': 0.50, 'rce': 0.40},
            'path': {'directory_traversal': 0.55, 'path_normalization': 0.35},
            'token': {'token_prediction': 0.30, 'token_replay': 0.25},
        }
        
        if param_type in priors and attack_type in priors[param_type]:
            return priors[param_type][attack_type]
        return 0.3  # Default prior
    
    def _recalculate_success_rate(self, pattern_key: str) -> None:
        """Recalculate success rate for a pattern."""
        if pattern_key in self.common_patterns:
            count = self.common_patterns[pattern_key]['count']
            # Simulate: for every 3 successes, assume 2 failures
            estimated_failures = max(0, int(count * 0.67))
            total = count + estimated_failures
            if total > 0:
                success_rate = count / total
                self.common_patterns[pattern_key]['success_rate'] = success_rate
    
    def get_learning_summary(self) -> Dict[str, Any]:
        """
        Get summary of what the system has learned.
        
        Returns:
            Dictionary with learning statistics
        """
        total_scans = len(self.scan_memory)
        total_successful = sum(count for _, count in self.successful_payloads_history.values())
        
        # Count total attempts per param_type
        param_attempts = {}
        param_successes = {}
        for pattern_key, stats in self.common_patterns.items():
            param_type = pattern_key.split('_')[0]
            if param_type not in param_attempts:
                param_attempts[param_type] = 0
                param_successes[param_type] = 0
            param_attempts[param_type] += stats['count']
            param_successes[param_type] += stats['count']
        
        return {
            'total_scans': total_scans,
            'total_successful_attacks': total_successful,
            'learned_patterns': dict(self.learned_patterns),
            'pattern_success_rates': self.pattern_success_rate,
            'common_patterns': self.common_patterns,
        }
    
    def suggest_next_attack(self, param_type: str, failed_attacks: List[str] = None) -> str:
        """
        Suggest the next attack to try based on success history.
        
        Args:
            param_type: Type of parameter being attacked
            failed_attacks: List of attacks already tried (to avoid repeating)
            
        Returns:
            Recommended attack type
        """
        if failed_attacks is None:
            failed_attacks = []
        
        ranked_attacks = self.get_attack_priority_for_parameter(param_type)
        
        # Pick the highest-success attack not yet tried
        for attack_type, success_rate in ranked_attacks:
            if attack_type not in failed_attacks:
                return attack_type
        
        # If all tried, return the one with lowest failure rate
        return ranked_attacks[0][0] if ranked_attacks else 'generic_payload'
    
    def should_retry_with_similar_pattern(self, param_type: str, 
                                          failed_attack: str, 
                                          threshold: float = 0.4) -> bool:
        """
        Decide if similar attacks should be retried based on pattern success.
        
        Args:
            param_type: Type of parameter
            failed_attack: Attack that failed
            threshold: Minimum success rate to justify retry
            
        Returns:
            True if pattern success rate is above threshold
        """
        ranked = self.get_attack_priority_for_parameter(param_type)
        for attack_type, success_rate in ranked:
            if attack_type != failed_attack and success_rate >= threshold:
                return True
        return False
    
    def export_learning_state(self) -> str:
        """
        Export current learning state as JSON for persistence.
        
        Returns:
            JSON string of learning state
        """
        exportable = {
            'learned_patterns': self.learned_patterns,
            'successful_payloads_history': self.successful_payloads_history,
            'common_patterns': self.common_patterns,
            'scan_count': len(self.scan_memory),
        }
        return json.dumps(exportable, indent=2)
    
    def import_learning_state(self, json_state: str) -> None:
        """
        Import previously saved learning state.
        
        Args:
            json_state: JSON string from export_learning_state()
        """
        try:
            state = json.loads(json_state)
            self.learned_patterns = state.get('learned_patterns', self.learned_patterns)
            self.successful_payloads_history = state.get('successful_payloads_history', {})
            self.common_patterns = state.get('common_patterns', self.common_patterns)
        except json.JSONDecodeError:
            pass  # Keep existing state if import fails
