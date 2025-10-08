import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.modules.fuzzing.hmac_fuzzer import HMACFuzzer

def test_hmac_vulnerabilities():
    """Example HMAC security testing"""
    
    print("🔐 HMAC Signature Security Testing")
    print("=" * 50)
    
    # Initialize HMAC fuzzer
    fuzzer = HMACFuzzer(secret_key="your-test-secret-key")
    
    # Create test ACP request
    test_request = {
        'method': 'POST', 
        'url': 'https://your-test-site.com/api/payments',
        'headers': {
            'Authorization': 'HMAC original_signature',
            'X-Timestamp': '2024-01-01T12:00:00Z',
            'Content-Type': 'application/json'
        },
        'body': {
            'amount': 100,
            'currency': 'USD',
            'order_id': 'test_order_123'
        }
    }
    
    # Generate test cases
    print("📋 Generating HMAC test cases...")
    test_cases = fuzzer.generate_test_cases(test_request)
    print(f"Generated {len(test_cases)} test cases")
    
    # Show some example test cases
    print("\n🧪 Sample test cases:")
    for i, case in enumerate(test_cases[:5]):
        print(f"  {i+1}. {case.get('description', 'No description')}")
    
    print("\n⚠️  Note: Actual testing requires authorized target")
    print("   Set ethical_mode=True and provide proper authorization")
    
    # Example of what would happen in real test
    print("\n📊 Example vulnerability analysis:")
    example_findings = [
        {
            'test_case': 'Signature manipulation: empty_signature',
            'severity': 5,
            'vulnerability_type': 'SIGNATURE_BYPASS',
            'evidence': ['Request accepted with empty signature']
        },
        {
            'test_case': 'Timestamp manipulation: future_timestamp', 
            'severity': 3,
            'vulnerability_type': 'TIMING_VULNERABILITY',
            'evidence': ['500ms timing difference detected']
        }
    ]
    
    for finding in example_findings:
        severity_icons = {5: '🔴', 4: '🟠', 3: '🟡', 2: '🔵', 1: '⚪️'}
        icon = severity_icons.get(finding['severity'], '⚪️')
        print(f"  {icon} {finding['test_case']}")
        print(f"     Type: {finding['vulnerability_type']}")
        print(f"     Evidence: {finding['evidence'][0]}")
    
    print(f"\n🎯 HMAC testing setup complete!")
    print("   Next: Implement actual HTTP requests with authorization")

if name == "__main__":
    test_hmac_vulnerabilities()
