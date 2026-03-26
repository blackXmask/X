"""
Realistic Failure Simulator - Human-Like Mistakes and Retries

Right now:

you're too perfect. try FOREVER until you succeed.
Real humans/systems:
- Make mistakes (use wrong payload)
- Retry with modifications
- Get blocked occasionally
- Forget previous failures

Add noise like:
{
    "mistake_made": true, 
    "recovery_attempt": true,
    "was_blocked": true
}

This is critical for ML training because it teaches the model:
"Sometimes even right payloads fail on first try. Persistence matters."
"A single attempt is not enough. You need adaptive retrying."
"""

from typing import Dict, List, Any, Tuple
import random


class RealisticFailureSimulator:
    """
    Simulates real-world failure modes and recovery behaviors.
    
    Prevents the dataset from being too clean (100% success rate).
    Teaches ML model about:
    - Initial failures followed by success
    - Wrong payloads that later succeed
    - Temporary blocks that go away
    - Adaptation and learning
    
    Attributes:
        failure_history: Record of failures and recoveries
        block_cache: Temporary blocks on payloads
    """
    
    def __init__(self):
        """Initialize failure simulator."""
        self.failure_history: List[Dict[str, Any]] = []
        self.block_cache: Dict[str, int] = {}  # payload → block_cycles_remaining
        
        # Probability of various failure modes
        self.failure_probabilities = {
            'initial_false_negative': 0.15,    # Should work but doesn't initially
            'wrong_payload_selection': 0.10,   # Human picks suboptimal payload
            'temporary_block': 0.08,           # Brief IP block
            'token_expiration': 0.05,          # Auth token expires mid-scan
            'rate_limit_backoff': 0.12,        # Rate limiting causes delays
            'retry_success': 0.70,             # Retry often succeeds
        }
        
        # Failure mode details
        self.failure_modes = {
            'initial_false_negative': {
                'description': 'Attack should work but times out',
                'recovery_strategies': ['retry_same_payload', 'wait_and_retry', 'reduce_timeout'],
                'typical_recovery_attempts': 2,
            },
            'wrong_payload_selection': {
                'description': 'Human picks suboptimal attack pattern',
                'recovery_strategies': ['switch_payload_variant', 'try_simpler_version'],
                'typical_recovery_attempts': 3,
            },
            'temporary_block': {
                'description': 'IP gets temporarily blocked by WAF/rate limiter',
                'recovery_strategies': ['wait_60_seconds', 'try_different_source', 'reduce_rate'],
                'typical_recovery_attempts': 1,
            },
            'token_expiration': {
                'description': 'Auth token expires during scan',
                'recovery_strategies': ['reauthenticate', 'get_new_token', 'refresh'],
                'typical_recovery_attempts': 1,
            },
            'rate_limit_backoff': {
                'description': 'Rate limit causes 429 responses',
                'recovery_strategies': ['exponential_backoff', 'space_out_requests', 're_attempt'],
                'typical_recovery_attempts': 2,
            },
        }
    
    def simulate_attack_attempt(self, endpoint: str, payload: str,
                               difficulty: str = 'medium') -> Dict[str, Any]:
        """
        Simulate realistic attack attempt with potential failures.
        
        Args:
            endpoint: Target endpoint
            payload: Attack payload
            difficulty: Attack difficulty (easy/medium/hard)
            
        Returns:
            Attempt result with potential failures
        """
        attempt = {
            'endpoint': endpoint,
            'payload': payload,
            'difficulty': difficulty,
            'attempt_number': 1,
            'success': True,
            'mistake_made': False,
            'recovery_required': False,
            'recovery_attempts': 0,
            'final_success': False,
            'failure_mode': None,
            'recovery_strategy': None,
        }
        
        # Check if payload is blocked
        if payload in self.block_cache and self.block_cache[payload] > 0:
            attempt['success'] = False
            attempt['failure_mode'] = 'temporary_block'
            self.block_cache[payload] -= 1
            return attempt
        
        # Determine if a failure occurs
        failure_occurs = self._should_failure_occur(difficulty)
        
        if failure_occurs:
            failure_mode = self._select_failure_mode()
            attempt['success'] = False
            attempt['failure_mode'] = failure_mode
            attempt['mistake_made'] = failure_mode in ['wrong_payload_selection']
            attempt['recovery_required'] = True
            
            # Simulate recovery
            recovery_data = self._simulate_recovery(failure_mode, endpoint, payload)
            attempt.update(recovery_data)
            
            # Record failure
            self.failure_history.append(attempt)
        else:
            attempt['final_success'] = True
            self.failure_history.append(attempt)
        
        return attempt
    
    def _should_failure_occur(self, difficulty: str) -> bool:
        """
        Determine if failure should occur based on attack difficulty.
        
        Args:
            difficulty: easy/medium/hard
            
        Returns:
            True if failure should happen
        """
        failure_rates = {
            'easy': 0.05,      # Easy attacks almost always work
            'medium': 0.15,    # Medium attacks sometimes fail
            'hard': 0.35,      # Hard attacks often fail initially
        }
        
        rate = failure_rates.get(difficulty, 0.15)
        return random.random() < rate
    
    def _select_failure_mode(self) -> str:
        """
        Select a failure mode based on probabilities.
        
        Returns:
            Failure mode name
        """
        # Weight-based selection
        modes_with_weights = [
            ('initial_false_negative', self.failure_probabilities['initial_false_negative']),
            ('wrong_payload_selection', self.failure_probabilities['wrong_payload_selection']),
            ('temporary_block', self.failure_probabilities['temporary_block']),
            ('token_expiration', self.failure_probabilities['token_expiration']),
            ('rate_limit_backoff', self.failure_probabilities['rate_limit_backoff']),
        ]
        
        total_weight = sum(w for _, w in modes_with_weights)
        rand_val = random.random() * total_weight
        
        cumulative = 0
        for mode, weight in modes_with_weights:
            cumulative += weight
            if rand_val < cumulative:
                return mode
        
        return 'rate_limit_backoff'
    
    def _simulate_recovery(self, failure_mode: str, endpoint: str,
                          payload: str) -> Dict[str, Any]:
        """
        Simulate recovery from failure.
        
        Args:
            failure_mode: Type of failure
            endpoint: Target endpoint
            payload: Original payload
            
        Returns:
            Recovery details
        """
        mode_config = self.failure_modes.get(failure_mode, {})
        recovery_strategies = mode_config.get('recovery_strategies', [])
        
        # Simulate recovery attempts
        recovery_data = {
            'recovery_required': True,
            'failure_mode': failure_mode,
            'recovery_attempts': 0,
            'final_success': False,
            'recovery_strategy_used': None,
        }
        
        max_attempts = mode_config.get('typical_recovery_attempts', 2)
        
        for attempt_num in range(1, max_attempts + 1):
            strategy = recovery_strategies[attempt_num - 1] if attempt_num <= len(recovery_strategies) else recovery_strategies[0]
            
            # Simulate recovery success probability
            recovery_success_prob = self._get_recovery_success_probability(failure_mode, attempt_num)
            
            recovery_data['recovery_attempts'] = attempt_num
            recovery_data['recovery_strategy_used'] = strategy
            
            if random.random() < recovery_success_prob:
                recovery_data['final_success'] = True
                break
        
        # If block, add to block cache
        if failure_mode == 'temporary_block':
            self.block_cache[payload] = 3  # Blocked for 3 cycles
        
        return recovery_data
    
    def _get_recovery_success_probability(self, failure_mode: str,
                                         attempt_number: int) -> float:
        """
        Get probability of recovery success based on attempt number.
        
        Args:
            failure_mode: Type of failure
            attempt_number: Which recovery attempt (1, 2, 3...)
            
        Returns:
            Success probability 0-1
        """
        base_success_prob = {
            'initial_false_negative': 0.90,    # Usually just needs retry
            'wrong_payload_selection': 0.60,   # Needs different payload
            'temporary_block': 0.85,           # Usually resolves wait
            'token_expiration': 0.95,          # Re-auth almost always works
            'rate_limit_backoff': 0.80,        # Backoff usually works
        }
        
        base = base_success_prob.get(failure_mode, 0.7)
        
        # Increase success rate with each attempt
        boost_per_attempt = 0.1
        adjusted = base + (attempt_number - 1) * boost_per_attempt
        
        return min(0.99, adjusted)
    
    def introduce_learning_mistake(self, endpoint: str, payload: str) -> Dict[str, Any]:
        """
        Introduce a "learning mistake" where human picks wrong payload.
        
        This simulates: "I'll try XSS injection when I should try SQL injection"
        
        Args:
            endpoint: Target endpoint  
            payload: Original (correct) payload
            
        Returns:
            Mistake scenario
        """
        mistake = {
            'endpoint': endpoint,
            'correct_payload': payload,
            'wrong_payload_tried_first': self._mutate_payload_incorrectly(payload),
            'mistake_rationale': 'Human chose suboptimal attack vector',
            'learning_occurs': True,
            'correct_solution_found_after': 2,  # Attempts before correction
            'lesson_learned': f'Parameter in {endpoint} is better attacked with different method',
        }
        
        return mistake
    
    def _mutate_payload_incorrectly(self, payload: str) -> str:
        """
        Create an incorrect mutation of payload (wrong approach).
        
        Args:
            payload: Original payload
            
        Returns:
            Mutated but suboptimal payload
        """
        mutations = [
            lambda p: '<img src=x onerror="' + p + '">',  # XSS wrapper (wrong for SQLi)
            lambda p: p.replace("'", "' OR '1'='1"),       # Generic SQLI (might not fit)
            lambda p: p + '%00',                           # Null byte (outdated)
            lambda p: 'A' * 50 + p[:30],                   # Overflow attempt (wrong)
        ]
        
        mutator = random.choice(mutations)
        return mutator(payload)
    
    def simulate_adaptive_retry(self, endpoint: str, original_payload: str,
                               attempt_count: int = 3) -> List[Dict[str, Any]]:
        """
        Simulate adaptive retry behavior (what real hackers do).
        
        Try same payload multiple ways, adapt after failures.
        
        Args:
            endpoint: Target endpoint
            original_payload: Original payload
            attempt_count: Number of attempts to simulate
            
        Returns:
            List of attempts showing adaptation
        """
        attempts = []
        
        for attempt_num in range(1, attempt_count + 1):
            # Payload may adapt after failure
            if attempt_num == 1:
                payload = original_payload
                approach = "first_try"
            elif attempt_num == 2:
                payload = original_payload.replace("'", "' OR '")  # Adapt
                approach = "adapted_syntax"
            else:
                payload = original_payload.upper()  # Different encoding
                approach = "encoding_variant"
            
            attempt = {
                'attempt_number': attempt_num,
                'endpoint': endpoint,
                'payload': payload,
                'approach': approach,
                'success': self._simulate_adaptive_success(attempt_num),
                'response_time': 0.5 + (attempt_num * 0.1),
                'adaptation_applied': attempt_num > 1,
            }
            
            attempts.append(attempt)
        
        return attempts
    
    def _simulate_adaptive_success(self, attempt_number: int) -> bool:
        """
        Simulate that later attempts have higher success (learning).
        
        Args:
            attempt_number: Which attempt (1, 2, 3...)
            
        Returns:
            Success probability increasing with attempts
        """
        # First attempt: 30% success
        # Second: 50%, Third: 70%
        success_rates = {
            1: 0.30,
            2: 0.50,
            3: 0.70,
            4: 0.85,
        }
        
        rate = success_rates.get(attempt_number, 0.85)
        return random.random() < rate
    
    def get_failure_statistics(self) -> Dict[str, Any]:
        """
        Get statistics on failure patterns.
        
        Returns:
            Failure statistics and recovery success rates
        """
        if not self.failure_history:
            return {'message': 'No failures recorded yet'}
        
        failure_modes = {}
        successes_after_recovery = 0
        
        for record in self.failure_history:
            if record['failure_mode']:
                mode = record['failure_mode']
                failure_modes[mode] = failure_modes.get(mode, 0) + 1
            
            if record.get('recovery_required') and record.get('final_success'):
                successes_after_recovery += 1
        
        recovery_success_rate = (
            successes_after_recovery / 
            sum(1 for r in self.failure_history if r.get('recovery_required'))
            if any(r.get('recovery_required') for r in self.failure_history)
            else 0
        )
        
        return {
            'total_attempts': len(self.failure_history),
            'failures_encountered': sum(1 for r in self.failure_history if not r.get('final_success')),
            'failure_recovery_rate': round(recovery_success_rate, 2),
            'failure_modes': failure_modes,
            'total_recovery_attempts': sum(r.get('recovery_attempts', 0) for r in self.failure_history),
            'average_recovery_attempts': round(
                sum(r.get('recovery_attempts', 0) for r in self.failure_history) / 
                max(1, len(self.failure_history)), 2
            ),
        }
    
    def get_mistake_analysis(self) -> Dict[str, Any]:
        """
        Analyze mistake patterns to understand learning.
        
        Returns:
            Mistakes made and lessons learned
        """
        failures_with_mistakes = [
            r for r in self.failure_history 
            if r.get('mistake_made')
        ]
        
        if not failures_with_mistakes:
            return {'message': 'No mistakes recorded', 'count': 0}
        
        return {
            'total_mistakes': len(failures_with_mistakes),
            'mistake_recovery_rate': sum(
                1 for r in failures_with_mistakes if r.get('final_success')
            ) / len(failures_with_mistakes),
            'mistakes_details': failures_with_mistakes[:10],  # First 10
        }
