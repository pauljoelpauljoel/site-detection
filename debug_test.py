import requests
import json

def test_url(url):
    print(f"Testing {url}...")
    try:
        res = requests.post('http://127.0.0.1:5000/predict', json={'url': url})
        print(f"Status: {res.status_code}")
        try:
            data = res.json()
            print("Fake Score Breakdown:", json.dumps(data.get('fake_score', {}).get('breakdown', {}), indent=2))
        except:
            print("Raw Response:", res.text)
    except Exception as e:
        print(f"Failed: {e}")

test_url('https://google.com')
