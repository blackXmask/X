"""
QUICK START GUIDE - Using the Upgraded Vulnerability Scanner

This script shows how to use the new BaselineEngine and PayloadMutationEngine
to scan with exploit confirmation and payload mutations.
"""

import asyncio
from .data import VulnerabilityDataCollector
from .baseline_engine import BaselineEngine
from .payload_mutation_engine import PayloadMutationEngine


async def scan_url_advanced(url: str, param: str = 'q'):
    """
    Scan a URL with:
    - Baseline comparison
    - Payload mutations
    - Exploit confirmation
    - Confidence scoring
    """
    
    # Initialize scanner
    collector = VulnerabilityDataCollector('../config/config.json')
    await collector.init_session()
    
    print(f"\n🔍 Scanning: {url}")
    print(f"📍 Parameter: {param}")
    print("=" * 60)
    
    # Get baseline (clean request without payload)
    print("\n[1/5] Capturing baseline response...")
    baseline = await collector.baseline_engine.get_baseline(url, 'GET')
    print(f"✓ Baseline captured | Size: {baseline['size']} bytes | Time: {baseline['time_ms']:.0f}ms")
    
    # Get XSS payloads from config
    xss_payloads = collector.config['payloads']['xss']
    print(f"\n[2/5] Testing {len(xss_payloads)} XSS payloads...")
    
    vulnerabilities = []
    
    for i, payload in enumerate(xss_payloads):
        # Skip if already found
        if len(vulnerabilities) > 0:
            break
        
        print(f"\n  Payload {i+1}/{len(xss_payloads)}: {payload[:40]}...")
        
        # Generate mutations of this payload
        mutations = collector.mutation_engine.generate_mutations(payload, mutation_count=3)
        print(f"    Generated {len(mutations)} mutations")
        
        for j, mutation in enumerate(mutations):
            print(f"    [{j+1}] Testing {mutation['mutation_type']}: ", end="")
            
            # Test the mutated payload
            result = await collector.test_payload(
                url=url,
                method='GET',
                param=param,
                payload=mutation['payload'],
                payload_type='xss',
                baseline_response=baseline,  # Use baseline for comparison
                mutation_type=mutation['mutation_type'],
                attempt_number=j + 1
            )
            
            if result is None:
                print("⚠️  Error")
                continue
            
            # Check if exploit confirmed
            exploit_confirmed = result['exploit_confirmed']
            confidence = result['confidence_score']
            reflected = result['payload_reflected']
            
            status = "✅ CONFIRMED" if exploit_confirmed else "❌ Not confirmed"
            print(f"{status} (conf: {confidence:.2f}, reflected: {reflected})")
            
            # If exploit confirmed, we found a vulnerability
            if exploit_confirmed:
                vulnerabilities.append({
                    'type': 'XSS',
                    'payload': mutation['payload'],
                    'mutation_type': mutation['mutation_type'],
                    'confidence': confidence,
                    'reflected': reflected,
                    'execution_signal': result.get('execution_signal', 'none'),
                    'anomaly_score': result.get('anomaly_score', 0)
                })
                print(f"\n🎯 VULNERABILITY FOUND!")
                break
    
    # Test SQL Injection
    if len(vulnerabilities) == 0:
        print(f"\n[3/5] Testing SQL injection payloads...")
        sqli_payloads = collector.config['payloads']['sqli']
        
        for i, payload in enumerate(sqli_payloads[:5]):  # Test first 5
            print(f"  Testing: {payload[:40]}... ", end="")
            
            result = await collector.test_payload(
                url=url,
                method='GET',
                param=param,
                payload=payload,
                payload_type='sqli',
                baseline_response=baseline,
                mutation_type='original',
                attempt_number=1
            )
            
            if result and result['exploit_confirmed']:
                print("✅ CONFIRMED!")
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'confidence': result['confidence_score'],
                    'time_anomaly': result.get('time_anomaly', False),
                    'execution_signal': result.get('execution_signal', 'none')
                })
                break
            else:
                print("❌")
    
    # Print results
    print("\n" + "=" * 60)
    print("[Results Summary]")
    print("=" * 60)
    
    if vulnerabilities:
        print(f"\n✅ Found {len(vulnerabilities)} vulnerability(ies):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln['type']}")
            print(f"   Confidence: {vuln['confidence']:.1%}")
            print(f"   Payload: {vuln['payload'][:60]}...")
            if 'mutation_type' in vuln:
                print(f"   Mutation: {vuln['mutation_type']}")
            if 'time_anomaly' in vuln and vuln['time_anomaly']:
                print(f"   ⏱️  Time-based attack detected")
            if 'reflected' in vuln and vuln['reflected']:
                print(f"   🌐 Payload reflected in response")
            if 'execution_signal' in vuln and vuln['execution_signal'] != 'none':
                print(f"   ⚡ Execution signal: {vuln['execution_signal']}")
            print()
    else:
        print("\n❌ No vulnerabilities found")
    
    # Print statistics
    print(f"\n📊 Statistics:")
    print(f"   Requests sent: {collector.stats['requests']}")
    print(f"   Vulnerabilities found: {collector.stats['vulns']}")
    print(f"   Errors: {collector.stats['errors']}")
    
    await collector.session.close()


async def scan_multiple_params(url: str, params: list = None):
    """
    Scan multiple parameters on a single URL.
    """
    if params is None:
        params = ['q', 'search', 'id', 'name', 'email', 'message']
    
    print(f"\n🚀 Advanced Scan: {url}")
    print(f"Testing parameters: {', '.join(params)}")
    
    for param in params:
        try:
            await scan_url_advanced(url, param)
        except Exception as e:
            print(f"❌ Error scanning parameter '{param}': {str(e)}")


async def test_payload_mutations():
    """
    Standalone test to see mutation engine in action.
    """
    print("\n🔬 Testing Payload Mutation Engine\n")
    
    engine = PayloadMutationEngine()
    
    payload = "<script>alert(1)</script>"
    print(f"Base payload: {payload}\n")
    
    mutations = engine.generate_mutations(payload, mutation_count=5)
    
    print(f"Generated {len(mutations)} mutations:\n")
    for i, mutation in enumerate(mutations, 1):
        print(f"{i}. {mutation['mutation_type']}")
        print(f"   Payload: {mutation['payload'][:60]}")
        print(f"   Bypass target: {mutation['bypass_target']}")
        print(f"   Complexity: {mutation['complexity_score']}/10\n")


# =====================================================
# MAIN - Choose which test to run
# =====================================================

if __name__ == "__main__":
    import sys
    
    # Run payload mutation demo
    print("\n" + "="*60)
    print("VULNERABILITY SCANNER - UPGRADED v2.0")
    print("="*60)
    asyncio.run(test_payload_mutations())
    
    # To scan a real target, uncomment below and add URL:
    # asyncio.run(scan_url_advanced("https://example.com/search", "q"))
    
    # To scan multiple parameters:
    # asyncio.run(scan_multiple_params("https://example.com", ['q', 'id', 'search']))
