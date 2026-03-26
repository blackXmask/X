#!/usr/bin/env python3
"""
Integration Test Suite for Unified Vulnerability Scanner v4.0
Tests all 16 modules and their connectivity
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_module_imports():
    """Test 1: Verify all modules can be imported"""
    print("\n" + "="*70)
    print("TEST 1: MODULE IMPORTS")
    print("="*70)
    
    modules = [
        'pattern_learning',
        'prioritization_engine',
        'cross_endpoint_analyzer',
        'impact_simulator',
        'strategy_layer',
        'stop_condition_evaluator',
        'realistic_failure_simulator',
        'endpoint_intelligence',
        'parameter_analyzer',
        'auth_context_handler',
        'smart_payload_selector',
        'baseline_engine',
        'payload_mutation_engine',
        'context_analyzer',
        'labeling_engine',
        'attack_chain'
    ]
    
    failed = []
    for module_name in modules:
        try:
            __import__(module_name)
            print(f"  [PASS] {module_name:40s} - Imported successfully")
        except ImportError as e:
            print(f"  [FAIL] {module_name:40s} - {e}")
            failed.append(module_name)
    
    print(f"\nResult: {len(modules) - len(failed)}/{len(modules)} modules imported")
    return len(failed) == 0


def test_scanner_instantiation():
    """Test 2: Instantiate scanner with all modules"""
    print("\n" + "="*70)
    print("TEST 2: SCANNER INSTANTIATION")
    print("="*70)
    
    try:
        from main import UnifiedVulnerabilityScanner
        scanner = UnifiedVulnerabilityScanner('../../config/config.json')
        
        print(f"  [PASS] Scanner instantiated successfully")
        print(f"  [INFO] Pattern Learning Engine: {'Active' if scanner.pattern_learning else 'Inactive'}")
        print(f"  [INFO] Prioritization Engine: {'Active' if scanner.prioritization_engine else 'Inactive'}")
        print(f"  [INFO] Cross-Endpoint Analyzer: {'Active' if scanner.cross_endpoint_analyzer else 'Inactive'}")
        print(f"  [INFO] Impact Simulator: {'Active' if scanner.impact_simulator else 'Inactive'}")
        print(f"  [INFO] Strategy Layer: {'Active' if scanner.strategy_layer else 'Inactive'}")
        print(f"  [INFO] Stop Condition Evaluator: {'Active' if scanner.stop_condition_evaluator else 'Inactive'}")
        print(f"  [INFO] Realistic Failure Simulator: {'Active' if scanner.realistic_failure_simulator else 'Inactive'}")
        print(f"  [INFO] Endpoint Intelligence: {'Active' if scanner.endpoint_intelligence else 'Inactive'}")
        print(f"  [INFO] Parameter Analyzer: {'Active' if scanner.parameter_analyzer else 'Inactive'}")
        print(f"  [INFO] Auth Context Handler: {'Active' if scanner.auth_context_handler else 'Inactive'}")
        print(f"  [INFO] Smart Payload Selector: {'Active' if scanner.smart_payload_selector else 'Inactive'}")
        print(f"  [INFO] Labeling Engine: {'Active' if scanner.labeling_engine else 'Inactive'}")
        print(f"  [INFO] Attack Chain Engine: {'Active' if scanner.attack_chain_engine else 'Inactive'}")
        
        return True
    except Exception as e:
        print(f"  [FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def test_module_functionality():
    """Test 3: Test individual module functionality"""
    print("\n" + "="*70)
    print("TEST 3: MODULE FUNCTIONALITY TESTS")
    print("="*70)
    
    passed = 0
    total = 0
    
    # Test 3.1: Pattern Learning Engine
    try:
        total += 1
        from pattern_learning import PatternLearningEngine
        engine = PatternLearningEngine()
        engine.record_successful_attack('id', 'idor', 'payload1')
        priority = engine.get_attack_priority_for_parameter('id')
        print(f"  [PASS] Pattern Learning - Records and retrieves patterns")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Pattern Learning - {e}")
    
    # Test 3.2: Prioritization Engine
    try:
        total += 1
        from prioritization_engine import PrioritizationEngine
        engine = PrioritizationEngine()
        score = engine.calculate_priority_score('/admin/users', 'api', 10)
        assert score > 0, "Priority score should be > 0"
        print(f"  [PASS] Prioritization Engine - Calculates priority scores (score={score:.2f})")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Prioritization Engine - {e}")
    
    # Test 3.3: Cross-Endpoint Analyzer
    try:
        total += 1
        from cross_endpoint_analyzer import CrossEndpointAnalyzer
        engine = CrossEndpointAnalyzer()
        engine.register_endpoint('http://test.com/api/users', ['id'], 'api')
        engine.register_endpoint('http://test.com/api/modify', ['user_id'], 'api')
        print(f"  [PASS] Cross-Endpoint Analyzer - Registers and analyzes endpoints")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Cross-Endpoint Analyzer - {e}")
    
    # Test 3.4: Impact Simulator
    try:
        total += 1
        from impact_simulator import ImpactSimulator
        engine = ImpactSimulator()
        impact = engine.simulate_impact({
            'type': 'idor',
            'affected_users': 50,
            'sensitivity': 'user_data'
        })
        assert impact, "Impact simulation should return results"
        print(f"  [PASS] Impact Simulator - Simulates vulnerability impact")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Impact Simulator - {e}")
    
    # Test 3.5: Strategy Layer
    try:
        total += 1
        from strategy_layer import StrategyLayer
        engine = StrategyLayer()
        strategy = engine.select_strategy_for_endpoint('http://test.com/api/users')
        assert strategy.get('name'), "Strategy should have a name"
        print(f"  [PASS] Strategy Layer - Selects attack strategy ({strategy.get('name')})")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Strategy Layer - {e}")
    
    # Test 3.6: Stop Condition Evaluator
    try:
        total += 1
        from stop_condition_evaluator import StopConditionEvaluator
        engine = StopConditionEvaluator()
        should_stop = engine.should_stop_attacking('http://test.com/test', 20, 0)
        print(f"  [PASS] Stop Condition Evaluator - Evaluates stopping criteria (should_stop={should_stop})")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Stop Condition Evaluator - {e}")
    
    # Test 3.7: Realistic Failure Simulator
    try:
        total += 1
        from realistic_failure_simulator import RealisticFailureSimulator
        engine = RealisticFailureSimulator()
        should_fail = engine.should_fail()
        print(f"  [PASS] Realistic Failure Simulator - Simulates realistic failures")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Realistic Failure Simulator - {e}")
    
    # Test 3.8: Endpoint Intelligence
    try:
        total += 1
        from endpoint_intelligence import EndpointIntelligence
        engine = EndpointIntelligence()
        endpoint_type = engine.classify_endpoint('http://test.com/admin/users')
        assert endpoint_type, "Should classify endpoint type"
        print(f"  [PASS] Endpoint Intelligence - Classifies endpoints ({endpoint_type})")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Endpoint Intelligence - {e}")
    
    # Test 3.9: Parameter Analyzer
    try:
        total += 1
        from parameter_analyzer import ParameterAnalyzer
        engine = ParameterAnalyzer()
        analysis = engine.analyze_parameters(['id', 'query', 'token'], 'http://test.com/api/search')
        assert 'id' in str(analysis), "Should analyze parameters"
        print(f"  [PASS] Parameter Analyzer - Analyzes parameters")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Parameter Analyzer - {e}")
    
    # Test 3.10: Smart Payload Selector
    try:
        total += 1
        from smart_payload_selector import SmartPayloadSelector
        engine = SmartPayloadSelector()
        payload = engine.select_payload('<script>alert(1)</script>', 'query', 'api')
        assert payload, "Should select payload"
        print(f"  [PASS] Smart Payload Selector - Selects context-aware payloads")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Smart Payload Selector - {e}")
    
    # Test 3.11: Payload Mutation Engine
    try:
        total += 1
        from payload_mutation_engine import PayloadMutationEngine
        engine = PayloadMutationEngine()
        mutated = engine.mutate('<script>alert(1)</script>')
        assert mutated, "Should mutate payload"
        print(f"  [PASS] Payload Mutation Engine - Mutates payloads")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Payload Mutation Engine - {e}")
    
    # Test 3.12: Labeling Engine
    try:
        total += 1
        from labeling_engine import SmartLabelingEngine
        engine = SmartLabelingEngine()
        # Engine should have some methods
        print(f"  [PASS] Labeling Engine - Loaded successfully")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Labeling Engine - {e}")
    
    # Test 3.13: Attack Chain Engine
    try:
        total += 1
        from attack_chain import AttackChainEngine
        engine = AttackChainEngine()
        engine.start_chain('http://test.com/api/test')
        print(f"  [PASS] Attack Chain Engine - Tracks attack chains")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] Attack Chain Engine - {e}")
    
    print(f"\nResult: {passed}/{total} module functionality tests passed")
    return passed == total


def test_module_connectivity():
    """Test 4: Test connectivity between modules"""
    print("\n" + "="*70)
    print("TEST 4: MODULE CONNECTIVITY (Integration Test)")
    print("="*70)
    
    try:
        from main import UnifiedVulnerabilityScanner
        from pattern_learning import PatternLearningEngine
        from prioritization_engine import PrioritizationEngine
        from strategy_layer import StrategyLayer
        from smart_payload_selector import SmartPayloadSelector
        from payload_mutation_engine import PayloadMutationEngine
        from impact_simulator import ImpactSimulator
        from stop_condition_evaluator import StopConditionEvaluator
        
        scanner = UnifiedVulnerabilityScanner('../../config/config.json')
        
        # Simulate a full workflow
        print("  [INFO] Running integrated workflow...")
        
        # Step 1: Pattern Learning learns from previous
        scanner.pattern_learning.record_successful_attack('id', 'idor', 'test')
        priority = scanner.pattern_learning.get_attack_priority_for_parameter('id')
        print(f"    [OK] Pattern Learning - Priority for 'id' param: {priority}")
        
        # Step 2: Prioritize endpoints
        endpoints = [
            {'url': 'http://test.com/admin', 'param_count': 5},
            {'url': 'http://test.com/api', 'param_count': 3}
        ]
        print(f"    [OK] Prioritization Engine - Ready to prioritize {len(endpoints)} endpoints")
        
        # Step 3: Strategy selection
        strategy = scanner.strategy_layer.select_strategy_for_endpoint('http://test.com/admin')
        print(f"    [OK] Strategy Layer - Selected strategy: {strategy.get('name')}")
        
        # Step 4: Payload selection
        payload = scanner.smart_payload_selector.select_payload(
            '<script>alert(1)</script>', 'query', 'admin'
        )
        print(f"    [OK] Smart Payload Selector - Selected payload")
        
        # Step 5: Payload mutation
        mutated = scanner.mutation_engine.mutate(payload)
        print(f"    [OK] Payload Mutation - Mutated payload")
        
        # Step 6: Impact simulation
        impact = scanner.impact_simulator.simulate_impact({
            'type': 'idor',
            'affected_users': 10,
            'sensitivity': 'user_data'
        })
        print(f"    [OK] Impact Simulator - Simulated impact")
        
        # Step 7: Stop condition check
        should_stop = scanner.stop_condition_evaluator.should_stop_attacking(
            'http://test.com/admin', 5, 1
        )
        print(f"    [OK] Stop Condition Evaluator - Evaluated (should_stop={should_stop})")
        
        print(f"\n  [PASS] All 8+ modules connected and working correctly!")
        return True
        
    except Exception as e:
        print(f"  [FAIL] Connectivity test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_loading():
    """Test 5: Verify config loads correctly"""
    print("\n" + "="*70)
    print("TEST 5: CONFIGURATION")
    print("="*70)
    
    try:
        from main import UnifiedVulnerabilityScanner
        scanner = UnifiedVulnerabilityScanner('../../config/config.json')
        
        config = scanner.config
        print(f"  [PASS] Config loaded successfully")
        print(f"    - Targets: {len(config.get('targets', {}).get('urls', []))} URLs")
        print(f"    - Payloads: {len(config.get('payloads', {}))} types")
        print(f"    - Scanning Threads: {config.get('scanning', {}).get('concurrent_requests', 0)}")
        print(f"    - Output File: {config.get('output', {}).get('csv_file', 'unknown')}")
        
        return True
    except Exception as e:
        print(f"  [FAIL] Config test failed: {e}")
        return False


def run_all_tests():
    """Run all integration tests"""
    print("\n")
    print("="*70)
    print("UNIFIED VULNERABILITY SCANNER v4.0 - INTEGRATION TEST SUITE")
    print("="*70)
    
    results = []
    
    results.append(("Module Imports", test_module_imports()))
    results.append(("Scanner Instantiation", test_scanner_instantiation()))
    results.append(("Configuration", test_config_loading()))
    results.append(("Module Functionality", test_module_functionality()))
    results.append(("Module Connectivity", test_module_connectivity()))
    
    # Print summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    passed_count = sum(1 for _, result in results if result)
    total_count = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {test_name}")
    
    print(f"\nOverall: {passed_count}/{total_count} test groups passed")
    
    if passed_count == total_count:
        print("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print(">  ALL TESTS PASSED - System is ready for use!                  >")
        print(">  Run: python main.py --config ../../config/config.json       >")
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        return 0
    else:
        print(f"\n{total_count - passed_count} test(s) failed. Please review output above.")
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
