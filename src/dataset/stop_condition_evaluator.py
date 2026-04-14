"""
Stop Condition Evaluator - Know When to Stop

Real scanners don't attack forever. They know when to stop because:
1. No new signals found (low_value) 
2. Blocked/WAF (blocked)
3. Exceeded limits (resource_exhausted)
4. Found good bug, moving to next target (vuln_found)

This prevents wasted effort and teaches the real hacker mindset:
"If it's not working and not going to work, try the next target."

Instead of: "Spending 1000 requests on endpoint that will never break"
Use: "Spend 50 requests, get signal → pivot or escalate. No signal → move on"
"""

from typing import Dict, List, Any, Tuple
from enum import Enum


class StopReasonEnum(Enum):
    """Reasons to stop attacking an endpoint."""
    VULN_FOUND = "vulnerability_found"           # Found real bug
    NO_SIGNAL = "no_signal_after_attempts"        # Nothing concrete
    WAF_BLOCKED = "waf_blocked_attacks"           # Blocked by firewall
    TIMEOUT_BLOCK = "timeout_rate_limited"        # Rate limited
    TOKEN_CYCLE = "auth_token_expired"            # Auth expired
    LOW_VALUE = "low_value_target"                # Not worth effort
    RESOURCE_EXHAUSTED = "resource_limit_hit"     # Budget exhausted
    STRATEGY_FAILED = "strategy_failed_pivot"     # Strategy not working
    DIMINISHING_RETURNS = "diminishing_returns"   # Signal plateau
    FALSE_POSITIVE = "false_positive_confirmed"   # Not real
    SERVICE_UNAVAILABLE = "service_unavailable"   # Endpoint down


class StopConditionEvaluator:
    """
    Determines when to stop attacking an endpoint.
    
    Implements intelligent stopping criteria to avoid:
    - Wasting scanner budget on hopeless targets
    - Triggering alarms after finding bug
    - Hammering blocked endpoints
    
    Attributes:
        evaluation_state: Current evaluation state
        stop_history: History of stop decisions
    """
    
    def __init__(self):
        """Initialize stop condition evaluator."""
        self.evaluation_state: Dict[str, Any] = {}
        self.stop_history: List[Dict[str, Any]] = []
        
        # Thresholds for stopping
        self.thresholds = {
            'max_attempts_no_signal': 20,      # Stop after 20 tries with no signal
            'max_waf_blocks': 3,               # Stop after 3 WAF blocks
            'max_timeouts': 5,                 # Stop after 5 timeouts
            'signal_plateau_threshold': 0.9,   # 90% of signals in 50% of attempts
            'min_exploitability_to_continue': 0.3,  # Keep going if >30% likely
        }
    
    def should_stop_attacking(self, endpoint: str,
                             attempts_made: int = 0,
                             signals_found: int = 0,
                             waf_blocks: int = 0,
                             timeouts: int = 0,
                             last_response_time: float = 0.0,
                             response_codes: List[int] = None,
                             endpoint_priority: float = 5.0) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Evaluate if we should stop attacking this endpoint.
        
        Args:
            endpoint: URL being tested
            attempts_made: Number of attacks tried
            signals_found: Number of positive signals
            waf_blocks: Number of WAF blocks detected
            timeouts: Number of timeouts/rate limits
            last_response_time: Last response time in seconds
            response_codes: List of HTTP response codes seen
            endpoint_priority: Priority score of endpoint (0-10)
            
        Returns:
            (should_stop: bool, stop_reason: str, analysis: dict)
        """
        if response_codes is None:
            response_codes = []
        
        analysis = {
            'endpoint': endpoint,
            'attempts': attempts_made,
            'signals': signals_found,
            'waf_blocks': waf_blocks,
            'timeouts': timeouts,
            'stop_reasons': [],
            'stop_signals': 0,
            'continue_signals': 0,
        }
        
        # 1. Check for definite STOP conditions
        
        # WAF Block Detection: 3+ blocks = stop
        if waf_blocks >= self.thresholds['max_waf_blocks']:
            analysis['stop_reasons'].append(StopReasonEnum.WAF_BLOCKED.value)
            analysis['stop_signals'] += 10
        
        # Timeout Detection: 5+ timeouts = stop
        if timeouts >= self.thresholds['max_timeouts']:
            analysis['stop_reasons'].append(StopReasonEnum.TIMEOUT_BLOCK.value)
            analysis['stop_signals'] += 10
        
        # Service Error: 503/504 repeatedly = stop
        if response_codes.count(503) >= 2 or response_codes.count(504) >= 2:
            analysis['stop_reasons'].append(StopReasonEnum.SERVICE_UNAVAILABLE.value)
            analysis['stop_signals'] += 8
        
        # 2. Check for vulnerability found (stop and report)
        if signals_found >= 3:  # Multiple signals = real find
            analysis['stop_reasons'].append(StopReasonEnum.VULN_FOUND.value)
            analysis['stop_signals'] += 15  # Strong stop signal
        
        # 3. Check for "no signal after many attempts"
        if attempts_made >= self.thresholds['max_attempts_no_signal'] and signals_found == 0:
            analysis['stop_reasons'].append(StopReasonEnum.NO_SIGNAL.value)
            analysis['stop_signals'] += 8
        
        # 4. Check for signal plateau (found good signals early then nothing)
        if attempts_made >= 10:
            early_attempts = attempts_made // 2
            if signals_found > 0:
                signal_ratio = signals_found / attempts_made
                early_signal_ratio = self._estimate_early_signals(attempts_made, signals_found) / max(1, early_attempts)
                
                if early_signal_ratio > 0.3 and signal_ratio < 0.1:
                    # Got signals early, now plateau = continue (something found)
                    analysis['continue_signals'] += 3
                elif signal_ratio >= 0.4:
                    # Good signal rate = continue
                    analysis['continue_signals'] += 5
        
        # 5. Priority-based stopping
        if endpoint_priority < 2.0 and attempts_made >= 10:
            analysis['stop_reasons'].append(StopReasonEnum.LOW_VALUE.value)
            analysis['stop_signals'] += 5
        
        # 6. Response time analysis (getting slower = might be detected)
        if last_response_time > 10.0 and attempts_made >= 5:
            # Response time explosion
            if timeouts == 0:  # Not timeout, just slow
                analysis['stop_reasons'].append(StopReasonEnum.TIMEOUT_BLOCK.value)
                analysis['stop_signals'] += 6
        
        # 7. False positive detection
        if signals_found > 0 and self._is_likely_false_positive(response_codes, signals_found):
            # FIXED: enum member name is FALSE_POSITIVE
            analysis['stop_reasons'].append(StopReasonEnum.FALSE_POSITIVE.value)
            analysis['stop_signals'] += 5
        
        # 8. Diminishing returns check
        if attempts_made >= 15:
            diminishing = self._check_diminishing_returns(attempts_made, signals_found)
            if diminishing:
                analysis['stop_reasons'].append(StopReasonEnum.DIMINISHING_RETURNS.value)
                analysis['stop_signals'] += 4
        
        # Decision: Should we stop?
        should_stop = analysis['stop_signals'] >= 8
        
        # But override: if found vuln, definitely stop (good!)
        if StopReasonEnum.VULN_FOUND.value in analysis['stop_reasons']:
            should_stop = True
        
        # Override: if very low priority and no signals, stop
        if endpoint_priority < 1.5 and signals_found == 0 and attempts_made >= 5:
            should_stop = True
        
        # Get primary stop reason
        primary_reason = analysis['stop_reasons'][0] if analysis['stop_reasons'] else 'unknown'
        
        # Store in history
        stop_decision = {
            'endpoint': endpoint,
            'should_stop': should_stop,
            'reason': primary_reason,
            'analysis': analysis,
        }
        self.stop_history.append(stop_decision)
        
        return should_stop, primary_reason, analysis
    
    def _estimate_early_signals(self, total_attempts: int, total_signals: int) -> int:
        """Estimate signals found in first half of attempts."""
        # Rough estimate: assume early attempts more fruitful
        return int(total_signals * 0.6) if total_signals > 0 else 0
    
    def _is_likely_false_positive(self, response_codes: List[int], 
                                 signals_found: int) -> bool:
        """
        Detect if signals are likely false positives.
        
        Args:
            response_codes: HTTP response codes seen
            signals_found: Number of signals detected
            
        Returns:
            True if likely false positive
        """
        # False positive indicators:
        # - Mostly 200 OK responses (no variation)
        # - No error codes for SQL injection attempts
        # - Same response size repeatedly
        
        if not response_codes:
            return False
        
        # If mostly 200s with no errors, might be false positive
        ok_ratio = response_codes.count(200) / len(response_codes)
        if ok_ratio > 0.95 and signals_found > 0:
            # Too consistent = reflection, not execution
            return True
        
        return False
    
    def _check_diminishing_returns(self, attempts: int, signals: int) -> bool:
        """
        Check if signals are plateauing (diminishing returns).
        
        Args:
            attempts: Total attempts made
            signals: Total signals found
            
        Returns:
            True if diminishing returns detected
        """
        if signals == 0:
            return True  # No signals = definitely diminishing
        
        signal_ratio = signals / attempts
        
        # If < 5% signal rate after 15 attempts, likely diminishing
        if signal_ratio < 0.05:
            return True
        
        return False
    
    def get_stop_recommendation(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get recommendation with reasoning.
        
        Args:
            stats: Dictionary with attempt stats
            
        Returns:
            Recommendation with explanation
        """
        endpoint = stats.get('endpoint', 'unknown')
        attempts = stats.get('attempts_made', 0)
        signals = stats.get('signals_found', 0)
        
        should_stop, reason, analysis = self.should_stop_attacking(
            endpoint,
            attempts,
            signals,
            stats.get('waf_blocks', 0),
            stats.get('timeouts', 0),
            stats.get('last_response_time', 0.0),
            stats.get('response_codes', []),
            stats.get('priority', 5.0),
        )
        
        if should_stop:
            action = "STOP"
            explanation = f"Stop because: {reason}"
        else:
            action = "CONTINUE"
            explanation = f"Continue attacking, {attempts} attempts, {signals} signals found"
        
        return {
            'action': action,
            'reason': reason,
            'explanation': explanation,
            'next_steps': self._get_next_steps(reason, signals),
            'detailed_analysis': analysis,
        }
    
    def _get_next_steps(self, stop_reason: str, signals_found: int) -> str:
        """Get recommended next steps."""
        if stop_reason == StopReasonEnum.VULN_FOUND.value:
            return "Report vulnerability, move to next endpoint"
        elif stop_reason == StopReasonEnum.WAF_BLOCKED.value:
            return "WAF detected, try different payloads with obfuscation before giving up"
        elif stop_reason == StopReasonEnum.TIMEOUT_BLOCK.value:
            return "Rate limited, slow down requests and try again after delay"
        elif stop_reason == StopReasonEnum.NO_SIGNAL.value:
            return "No signals after many attempts, move to next endpoint"
        elif stop_reason == StopReasonEnum.LOW_VALUE.value:
            return "Low value target, allocate resources to higher priority endpoints"
        elif stop_reason == StopReasonEnum.FALSE_POSITIVE_CONFIRMED.value:
            return "False positive confirmed, move to next target"
        else:
            return "Move to next endpoint or strategy"
    
    def get_stop_summary(self) -> Dict[str, Any]:
        """
        Get summary of stop decisions made.
        
        Returns:
            Statistics about stopping patterns
        """
        if not self.stop_history:
            return {'message': 'No stop decisions recorded yet'}
        
        reasons = {}
        for decision in self.stop_history:
            reason = decision['reason']
            reasons[reason] = reasons.get(reason, 0) + 1
        
        stopped_count = sum(1 for d in self.stop_history if d['should_stop'])
        continued_count = len(self.stop_history) - stopped_count
        
        return {
            'total_decisions': len(self.stop_history),
            'stopped_count': stopped_count,
            'continued_count': continued_count,
            'stop_distribution': reasons,
            'stop_rate': round(stopped_count / len(self.stop_history), 2),
        }
