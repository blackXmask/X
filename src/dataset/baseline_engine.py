"""
Baseline Engine - Compares responses with and without payloads for accurate vulnerability detection.

Key Features:
- Captures baseline (clean) request response
- Compares attacked response against baseline
- Detects time-based, boolean-based, and content-based anomalies
- Provides metrics for ML features
"""

import asyncio
import aiohttp
import hashlib
import time
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
import re


class BaselineEngine:
    """Manages baseline requests and comparison analysis."""
    
    def __init__(self, session: aiohttp.ClientSession, timeout: int = 15, slow_threshold: float = 5.0):
        """
        Args:
            session: aiohttp ClientSession for requests
            timeout: Request timeout in seconds
            slow_threshold: Time threshold (seconds) for detecting time-based attacks
        """
        self.session = session
        self.timeout = timeout
        self.slow_threshold = slow_threshold
        self.baselines: Dict[str, Dict] = {}  # Cache baselines by URL
    
    async def get_baseline(self, url: str, method: str = 'GET', force_refresh: bool = False) -> Optional[Dict]:
        """
        Capture baseline response (clean request without payload).
        
        Returns Dict with:
            - status: HTTP status code
            - time_ms: Response time in milliseconds
            - size: Response size in bytes
            - hash: SHA256 hash of response body
            - content_preview: First 5000 chars of response
            - headers: Response headers
            - timestamp: When baseline was captured
        """
        cache_key = f"{method}:{url}"
        
        # Return cached baseline if available
        if cache_key in self.baselines and not force_refresh:
            return self.baselines[cache_key]
        
        try:
            start_time = time.time()
            
            async with self.session.request(method, url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                content = await resp.text()
                
                baseline = {
                    'status': resp.status,
                    'time_ms': response_time,
                    'size': len(content),
                    'hash': hashlib.sha256(content.encode()).hexdigest(),
                    'content_preview': content[:5000],
                    'headers': dict(resp.headers),
                    'timestamp': time.time(),
                    'content_full': content  # For detailed comparison
                }
                
                # Cache the baseline
                self.baselines[cache_key] = baseline
                return baseline
        
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            return None
    
    async def compare_responses(self, url: str, method: str, baseline: Dict, 
                               attacked_response: Dict, payload: str) -> Dict:
        """
        Compare attacked response against baseline.
        
        Returns comparison metrics:
            - status_diff: boolean, True if status code changed
            - time_diff_ms: Time difference in milliseconds
            - size_diff: Size difference in bytes
            - size_diff_percent: Percentage change in size
            - content_unchanged: boolean, True if content is identical
            - content_diff_ratio: Levenshtein-like difference ratio (0-1)
            - reflection_detected: boolean, True if payload appears in response
            - reflection_context: Where payload was found (html/js/attribute/json/url)
            - encoding_detected: What encoding applied (url/html/unicode/double/none)
            - time_anomaly: boolean, True if response time is suspiciously different
            - status_anomaly: boolean, True if status changed unexpectedly
            - content_anomaly: boolean, True if content changed significantly
        """
        attacked_content = attacked_response.get('content', '')
        baseline_content = baseline.get('content_preview', '')
        
        # Time-based metrics
        time_diff = attacked_response['time_ms'] - baseline['time_ms']
        time_anomaly = time_diff > (self.slow_threshold * 1000)
        
        # Size-based metrics
        size_diff = attacked_response['size'] - baseline['size']
        baseline_size = baseline['size']
        size_diff_percent = (size_diff / baseline_size * 100) if baseline_size > 0 else 0
        
        # Content comparison
        content_unchanged = attacked_response.get('hash') == baseline['hash']
        content_diff_ratio = self._calculate_content_diff(baseline_content, attacked_content[:5000])
        content_anomaly = content_diff_ratio > 0.15  # 15% threshold
        
        # Status code comparison
        status_diff = attacked_response['status'] != baseline['status']
        status_anomaly = status_diff and attacked_response['status'] >= 400
        
        # Payload reflection analysis
        reflection_data = self._analyze_reflection(payload, attacked_content)
        
        return {
            # Time metrics
            'time_diff_ms': time_diff,
            'time_anomaly': time_anomaly,
            'is_time_based_blind': time_diff > (self.slow_threshold * 1000),
            
            # Size metrics
            'size_diff': size_diff,
            'size_diff_percent': round(size_diff_percent, 2),
            'size_anomaly': abs(size_diff_percent) > 10,  # 10% threshold
            
            # Content metrics
            'content_unchanged': content_unchanged,
            'content_diff_ratio': round(content_diff_ratio, 4),
            'content_anomaly': content_anomaly,
            
            # Status metrics
            'status_diff': status_diff,
            'status_anomaly': status_anomaly,
            'baseline_status': baseline['status'],
            'attacked_status': attacked_response['status'],
            
            # Reflection metrics
            'payload_reflected': reflection_data['reflected'],
            'reflection_count': reflection_data['count'],
            'reflection_context': reflection_data['context'],
            'reflection_position': reflection_data['position'],
            'payload_encoded': reflection_data['encoded'],
            'encoding_detected': reflection_data['encoding_type'],
            
            # Combined anomaly score
            'anomaly_score': self._calculate_anomaly_score(time_diff, size_diff_percent, content_diff_ratio),
            'is_likely_vulnerable': self._is_likely_vulnerable(time_diff, content_diff_ratio, reflection_data)
        }
    
    def _analyze_reflection(self, payload: str, response: str) -> Dict:
        """
        Analyze how the payload is reflected in response.
        
        Returns:
            - reflected: bool, True if payload found in response
            - count: int, number of reflections
            - context: str, where found (html/js/attribute/json/url/text)
            - position: int or list, character position(s)
            - encoded: bool, True if payload was encoded
            - encoding_type: str (utf8/html/url/unicode/double/none)
        """
        result = {
            'reflected': False,
            'count': 0,
            'context': [],
            'position': [],
            'encoded': False,
            'encoding_type': 'none'
        }
        
        # Direct reflection
        if payload in response:
            result['reflected'] = True
            result['count'] = response.count(payload)
            positions = [m.start() for m in re.finditer(re.escape(payload), response)]
            result['position'] = positions[0] if positions else -1
            return result
        
        # URL encoded reflection
        from urllib.parse import quote
        encoded_url = quote(payload)
        if encoded_url in response:
            result['reflected'] = True
            result['encoded'] = True
            result['encoding_type'] = 'url'
            result['count'] = response.count(encoded_url)
            positions = [m.start() for m in re.finditer(re.escape(encoded_url), response)]
            result['position'] = positions[0] if positions else -1
            return result
        
        # HTML encoded reflection
        import html
        encoded_html = html.escape(payload)
        if encoded_html in response:
            result['reflected'] = True
            result['encoded'] = True
            result['encoding_type'] = 'html'
            result['count'] = response.count(encoded_html)
            positions = [m.start() for m in re.finditer(re.escape(encoded_html), response)]
            result['position'] = positions[0] if positions else -1
            return result
        
        # Double URL encoded
        encoded_url_double = quote(encoded_url)
        if encoded_url_double in response:
            result['reflected'] = True
            result['encoded'] = True
            result['encoding_type'] = 'double_url'
            result['count'] = response.count(encoded_url_double)
            positions = [m.start() for m in re.finditer(re.escape(encoded_url_double), response)]
            result['position'] = positions[0] if positions else -1
            return result
        
        # Analyze context where payload might appear
        context_patterns = {
            'in_html_tag': r'<[^>]*' + re.escape(payload)[:20] + r'[^>]*>',
            'in_js': r'<script[^>]*>.*?' + re.escape(payload)[:20] + r'.*?</script>',
            'in_attribute': r'\s+\w+\s*=\s*["\'].*?' + re.escape(payload)[:20] + r'.*?["\']',
            'in_json': r'\{.*?"[^"]*' + re.escape(payload)[:20] + r'[^"]*".*?\}',
            'in_url': r'(?:src|href|action)\s*=\s*["\'].*?' + re.escape(payload)[:20]
        }
        
        for context_type, pattern in context_patterns.items():
            if re.search(pattern, response[:10000], re.IGNORECASE | re.DOTALL):
                result['context'].append(context_type)
        
        return result
    
    def _calculate_content_diff(self, baseline: str, attacked: str) -> float:
        """
        Calculate similarity ratio between baseline and attacked content.
        Uses simple length-based heuristic + character overlap.
        
        Returns: float between 0 (completely different) and 1 (identical)
        """
        if len(baseline) == 0 and len(attacked) == 0:
            return 0.0
        
        if baseline == attacked:
            return 0.0  # No difference (0 diff means no anomaly)
        
        # Calculate length difference ratio
        max_len = max(len(baseline), len(attacked))
        length_diff = abs(len(baseline) - len(attacked)) / max_len if max_len > 0 else 0
        
        # Calculate character overlap
        baseline_chars = set(baseline)
        attacked_chars = set(attacked)
        if baseline_chars:
            overlap = len(baseline_chars & attacked_chars) / len(baseline_chars)
        else:
            overlap = 0
        
        # Combined diff ratio (higher = more different)
        diff_ratio = (length_diff + (1 - overlap)) / 2
        return min(diff_ratio, 1.0)
    
    def _calculate_anomaly_score(self, time_diff_ms: float, size_diff_percent: float, 
                                content_diff_ratio: float) -> float:
        """
        Calculate combined anomaly score (0-1, higher = more anomalous).
        
        Weights:
            - Time: 0.3 (delay attacks)
            - Size: 0.3 (response manipulation)
            - Content: 0.4 (actual exploitation evidence)
        """
        # Normalize metrics to 0-1 range
        time_score = min(abs(time_diff_ms) / (self.slow_threshold * 1000), 1.0)
        size_score = min(abs(size_diff_percent) / 100, 1.0)
        content_score = content_diff_ratio
        
        # Weighted average
        anomaly = (time_score * 0.3) + (size_score * 0.3) + (content_score * 0.4)
        return round(anomaly, 3)
    
    def _is_likely_vulnerable(self, time_diff_ms: float, content_diff_ratio: float, 
                             reflection_data: Dict) -> bool:
        """
        Quick heuristic to flag as likely vulnerable.
        
        True if:
            - Payload is reflected, OR
            - Content changed significantly, OR  
            - Time delay is suspicious
        """
        return (
            reflection_data['reflected'] or
            content_diff_ratio > 0.20 or
            time_diff_ms > (self.slow_threshold * 1000)
        )
    
    def clear_cache(self):
        """Clear baseline cache (useful between target switches)."""
        self.baselines.clear()
    
    def get_cached_baseline(self, url: str, method: str = 'GET') -> Optional[Dict]:
        """Get cached baseline without making new request."""
        cache_key = f"{method}:{url}"
        return self.baselines.get(cache_key)
