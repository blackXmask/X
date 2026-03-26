"""
Smart Labeling Engine - Generates TRUE LABELS based on REAL EXPLOITABILITY.

Priority 4: Realistic Labeling
- Label based on real exploitability, not just reflection/errors
- Track false positives (escaped output, harmless errors, no impact)
- Bug bounty validity assessment
- Impact scoring for triaging

This is what separates a toy dataset from production-grade dataset.
Labels are what ML models learn from - bad labels = bad model.
"""

from typing import Dict, Optional, List


class SmartLabelingEngine:
    """Generates reliable labels by combining multiple confirmation signals."""
    
    def __init__(self):
        """Initialize labeling thresholds."""
        self.reflection_weight = 0.25      # Payload was echoed back
        self.execution_weight = 0.35       # Actual code/command executed
        self.anomaly_weight = 0.20         # Response changed significantly
        self.error_weight = 0.20            # Error message revealed

    def generate_label(self, 
                      vulnerability_detected: bool,
                      exploit_confirmed: bool,
                      confidence_score: float,
                      execution_signals: List[str],
                      reflection_present: bool,
                      anomaly_score: float,
                      payload_type: str,
                      endpoint_type: str = 'other',
                      sensitivity_level: str = 'unknown',
                      auth_required: bool = False) -> Dict:
        """
        Generate TRUE LABEL (0 or 1) based on REAL EXPLOITABILITY.
        
        Unlike simple labels, this considers:
        - Real impact (reflection alone doesn't count)
        - Bug bounty validity (is this a real vulnerability?)
        - False positive risk (escaped output, harmless errors)
        - Endpoint sensitivity (same vuln = higher impact on sensitive endpoint)
        - Authentication context (privilege escalation vs guest)
        
        Returns:
            {
                'label': 0 or 1,                    # BINARY: exploitable or not
                'exploit_type': 'reflected_xss/...', # What kind of vuln
                'real_vulnerability': bool,         # Is it REAL? (not false positive)
                'exploitable': bool,                # Can attacker abuse it?
                'impact': 'low/medium/high',       # Potential impact
                'bug_bounty_valid': bool,          # Worth reporting?
                'false_positive': bool,            # False alarm?
                'false_positive_reason': str,      # Why it's false positive
                'confidence_factors': {...},
                'label_reasoning': str,
                'privileged_escalation': bool,     # Admin vs guest difference?
            }
        """
        
        # Signal 1: Reflection-based
        reflection_score = 0.8 if reflection_present else 0.0
        
        # Signal 2: Execution (STRONGEST signal)
        execution_score = self._score_execution_signals(execution_signals, payload_type)
        
        # Signal 3: Anomaly in response
        anomaly_score_normalized = min(anomaly_score / 100, 1.0)
        
        # Signal 4: Pattern detection confidence
        pattern_score = confidence_score if vulnerability_detected else 0.0
        
        # Weighted combination
        weighted_score = (
            reflection_score * self.reflection_weight +
            execution_score * self.execution_weight +
            anomaly_score_normalized * self.anomaly_weight +
            pattern_score * self.error_weight
        )
        
        # Check if false positive
        is_false_positive, false_positive_reason = self._assess_false_positive(
            payload_type,
            reflection_present,
            execution_score,
            anomaly_score_normalized,
            weighted_score
        )
        
        # Determine real exploitability (not just detection)
        real_vulnerability = self._is_real_vulnerability(
            exploit_confirmed,
            execution_score,
            is_false_positive,
            payload_type
        )
        
        # Check exploitability
        exploitable = real_vulnerability and weighted_score >= 0.50
        
        # Impact assessment
        impact = self._calculate_impact(
            payload_type,
            endpoint_type,
            sensitivity_level,
            auth_required,
            execution_score
        )
        
        # Bug bounty validity
        bug_bounty_valid = self._is_bug_bounty_valid(
            real_vulnerability,
            impact,
            is_false_positive,
            payload_type
        )
        
        # Privilege escalation?
        privileged_escalation = auth_required and payload_type in ['idor', 'bypass']
        
        # Final label decision: real exploitability, not just detection
        if real_vulnerability and exploitable and not is_false_positive:
            label = 1
            reliability = 'high' if weighted_score >= 0.80 else 'medium'
        elif exploit_confirmed and weighted_score >= 0.65:
            label = 1
            reliability = 'medium'
        else:
            label = 0
            reliability = 'high' if weighted_score < 0.3 else 'medium'
        
        # Classify exploit type
        exploit_type = self._classify_exploit_type(
            payload_type,
            execution_signals,
            reflection_present
        )
        
        reasoning = self._generate_detailed_reasoning(
            label,
            real_vulnerability,
            is_false_positive,
            execution_signals,
            weighted_score,
            impact,
            bug_bounty_valid
        )
        
        return {
            'label': label,
            'exploit_type': exploit_type,
            'real_vulnerability': real_vulnerability,
            'exploitable': exploitable,
            'impact': impact,
            'bug_bounty_valid': bug_bounty_valid,
            'false_positive': is_false_positive,
            'false_positive_reason': false_positive_reason,
            'privileged_escalation': privileged_escalation,
            'exploit_reliability': reliability,
            'confidence_factors': {
                'reflection': round(reflection_score, 3),
                'execution': round(execution_score, 3),
                'anomaly': round(anomaly_score_normalized, 3),
                'pattern': round(pattern_score, 3),
                'weighted_score': round(weighted_score, 3),
            },
            'label_reasoning': reasoning,
        }
    
    def _assess_false_positive(
        self,
        payload_type: str,
        reflection: bool,
        execution_score: float,
        anomaly_score: float,
        weighted_score: float
    ) -> tuple:
        """
        Assess if this is a false positive (not real vulnerability).
        
        Common false positives:
        - Reflected but escaped/sanitized output
        - Error messages that are harmless
        - Static file returns
        - Timeouts on non-delay attacks
        """
        # Strong execution signals = not false positive
        if execution_score >= 0.85:
            return False, None
        
        # Reflection alone without execution = risky
        if reflection and execution_score == 0:
            return True, "reflected_but_escaped"
        
        # Very small anomaly without other signals = probably false positive
        if weighted_score < 0.3:
            return True, "minimal_signals"
        
        # Error reflection without execution = false positive
        if anomaly_score < 0.3 and reflection:
            return True, "error_reflection_no_impact"
        
        return False, None
    
    def _is_real_vulnerability(
        self,
        exploit_confirmed: bool,
        execution_score: float,
        is_false_positive: bool,
        payload_type: str
    ) -> bool:
        """
        Determine if this is a REAL vulnerability (not just scanner noise).
        
        Real vulnerabilities have:
        - Execution signals (code ran)
        - Confirmed exploitation
        - Not a false positive
        """
        if is_false_positive:
            return False
        
        if execution_score >= 0.8:
            return True
        
        if exploit_confirmed and execution_score >= 0.5:
            return True
        
        return False
    
    def _calculate_impact(
        self,
        payload_type: str,
        endpoint_type: str,
        sensitivity_level: str,
        auth_required: bool,
        execution_score: float
    ) -> str:
        """Calculate potential impact of vulnerability."""
        base_impact = {
            'xss': 'low',
            'sqli': 'high',
            'command_injection': 'critical',
            'idor': 'medium',
            'ssrf': 'high',
            'path_traversal': 'high',
            'xxe': 'high',
            'file_upload': 'high',
            'template_injection': 'high',
        }
        
        impact = base_impact.get(payload_type, 'medium')
        
        # Boost impact on sensitive endpoints
        if sensitivity_level in ['config', 'payment']:
            impact_levels = {'low': 'medium', 'medium': 'high', 'high': 'critical'}
            impact = impact_levels.get(impact, impact)
        
        # Privilege escalation on admin = critical
        if auth_required and endpoint_type in ['admin', 'dashboard']:
            impact = 'critical'
        
        # No execution = lower impact
        if execution_score < 0.5:
            impact_levels = {'critical': 'high', 'high': 'medium', 'medium': 'low'}
            impact = impact_levels.get(impact, impact)
        
        return impact
    
    def _is_bug_bounty_valid(
        self,
        real_vulnerability: bool,
        impact: str,
        is_false_positive: bool,
        payload_type: str
    ) -> bool:
        """
        Determine if vulnerability is worth reporting in bug bounty.
        
        Bug bounties only care about:
        - Real vulnerabilities
        - Non-trivial impact
        - Not simple bypasses
        """
        if is_false_positive or not real_vulnerability:
            return False
        
        # Low impact not worth reporting
        if impact == 'low':
            return False
        
        # Most medium+ severity vulnerabilities are worth reporting
        return impact in ['medium', 'high', 'critical']
    
    def _generate_detailed_reasoning(
        self,
        label: int,
        real_vulnerability: bool,
        is_false_positive: bool,
        signals: List[str],
        score: float,
        impact: str,
        bug_bounty_valid: bool
    ) -> str:
        """Generate detailed muli-part reasoning for labeling decision."""
        parts = []
        
        if label == 1:
            parts.append("VULNERABLE")
        else:
            parts.append("CLEAN")
        
        if real_vulnerability:
            parts.append("Real vulnerability confirmed")
        
        if is_false_positive:
            parts.append(f"False positive warning")
        
        if signals:
            parts.append(f"Signals: {','.join(signals[:3])}")
        
        parts.append(f"Score: {score:.2f}")
        parts.append(f"Impact: {impact}")
        
        if bug_bounty_valid:
            parts.append("Bug bounty worthy")
        
        return " | ".join(parts)
    
    def _score_execution_signals(self, signals: List[str], payload_type: str) -> float:
        """
        Score execution signals - actual proof of exploitation.
        
        This is the strongest signal - if we see actual execution, label = 1
        """
        if not signals or signals == ['none']:
            return 0.0
        
        score = 0.0
        
        # Execution proof signals
        execution_proofs = {
            'js_executed': 0.95,           # JavaScript actually ran
            'command_executed': 1.0,       # Command output leaked
            'file_read': 1.0,              # File system accessed
            'data_leak': 0.9,              # Data exfiltrated
            'template_exec': 0.95,         # Template code ran
            'dom_execution': 0.85,         # DOM manipulation detected
            'sql_executed': 0.9,           # SQL executed (error or data leak)
        }
        
        for signal in signals:
            score = max(score, execution_proofs.get(signal, 0.0))
        
        return min(score, 1.0)
    
    def _generate_reasoning(self,
                           exploit_confirmed: bool,
                           signals: List[str],
                           reflection: bool,
                           score: float,
                           payload_type: str) -> str:
        """Generate human-readable explanation for the label."""
        
        parts = []
        
        if exploit_confirmed:
            parts.append("Multi-signal exploitation confirmed")
        
        if signals and signals != ['none']:
            signal_names = ', '.join(signals)
            parts.append(f"Execution signals: {signal_names}")
        
        if reflection:
            parts.append("Payload reflected in response")
        
        parts.append(f"Confidence: {score:.1%}")
        
        return " | ".join(parts)
    
    def _assess_false_positive_risk(self,
                                   label: int,
                                   reflection: bool,
                                   execution: float,
                                   anomaly: float) -> str:
        """Assess likelihood of false positive."""
        
        if label == 0:
            return 'low'  # Clean request = low false positive
        
        # For positives, check for risky patterns
        if execution >= 0.5:
            return 'low'  # Execution signals = high confidence
        
        if reflection and anomaly >= 0.5:
            return 'low'  # Reflection + anomaly = reliable
        
        if reflection and not anomaly:
            return 'medium'  # Reflection alone could be false positive
        
        if anomaly >= 0.7:
            return 'medium'  # High anomaly but no other proof = might be FP
        
        return 'high'  # Single weak signal = risky
    
    def _classify_exploit_type(self, 
                             payload_type: str,
                             signals: List[str],
                             reflected: bool) -> str:
        """Classify exact type of exploitation."""
        
        # If we detected execution, use that
        if 'js_executed' in signals:
            return 'reflected_xss' if reflected else 'dom_xss'
        
        if 'command_executed' in signals:
            return 'command_injection'
        
        if 'sql_executed' in signals:
            return 'sql_injection'
        
        if 'file_read' in signals:
            return 'path_traversal'
        
        if 'template_exec' in signals:
            return 'template_injection'
        
        if 'data_leak' in signals:
            return 'idor' if 'id' in payload_type else 'information_disclosure'
        
        # Fall back to payload type
        type_map = {
            'xss': 'reflected_xss' if reflected else 'dom_xss',
            'sqli': 'boolean_sqli' if 'select' in str(signals).lower() else 'error_sqli',
            'command': 'command_injection',
            'path_traversal': 'path_traversal',
            'idor': 'idor',
            'ssrf': 'ssrf',
            'xxe': 'xxe_injection',
            'ssti': 'template_injection',
        }
        
        return type_map.get(payload_type, 'unknown_vulnerability')
