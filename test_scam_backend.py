import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

from app import analyze_phone_number

def test_backend():
    print("Testing Scam Call Detection Backend...")
    
    # Test 1: Safe Number
    res = analyze_phone_number("+12025550100")
    print(f"Test 1 (Safe): Status={res['status']}, Risk={res['risk']}")
    assert res['status'] == 'Safe'

    # Test 2: Blacklisted
    res = analyze_phone_number("+1234567890")
    print(f"Test 2 (Blacklist): Status={res['status']}, Risk={res['risk']}")
    assert res['status'] == 'Scam'
    assert 'Blacklisted' in res['reasons'][0]

    # Test 3: Prefix (+234)
    res = analyze_phone_number("+2348012345678")
    print(f"Test 3 (Prefix +234): Status={res['status']}, Risk={res['risk']}")
    assert res['status'] == 'Scam'
    assert 'high-risk prefix' in res['reasons'][0]

    # Test 4: Pattern (Repeated)
    res = analyze_phone_number("+15555555555")
    print(f"Test 4 (Pattern): Status={res['status']}, Risk={res['risk']}")
    # Might be Suspicious or Scam depending on logic, but risk should be elevated
    assert res['status'] in ['Suspicious', 'Scam']

    print("All tests passed!")

if __name__ == "__main__":
    try:
        test_backend()
    except Exception as e:
        print(f"Test Failed: {e}")
        exit(1)
