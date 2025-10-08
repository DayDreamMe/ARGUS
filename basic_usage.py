import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.argus_orchestrator import ArgusAuditor

def main():
    """Example security audit"""
    
    # Initialize auditor
    auditor = ArgusAuditor(
        target_domain="example-shop.com",
        ethical_mode=True
    )
    
    # Authorize testing (in real usage, provide actual auth data)
    auth_data = {
        'type': 'owner',
        'contact_email': 'security@example-shop.com',
        'scope': ['api_testing', 'fuzzing']
    }
    
    if not auditor.authorize(auth_data):
        print("❌ Authorization failed. Cannot proceed.")
        return
        
    print("✅ Authorization successful. Starting audit...")
    
    # Run comprehensive audit
    try:
        report = auditor.run_comprehensive_audit()
        
        # Generate readable report
        readable_report = auditor.generate_report(report, format='json')
        print("\n" + "="*50)
        print("SECURITY AUDIT REPORT")
        print("="*50)
        print(readable_report)
        
        # Save to file
        with open('security_audit.json', 'w') as f:
            f.write(readable_report)
        print("\n📄 Report saved to 'security_audit.json'")
        
    except Exception as e:
        print(f"❌ Audit failed: {e}")

if name == "__main__":
    main()
