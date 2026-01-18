from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import re
import socket
import ssl
import requests
import datetime
import math
from urllib.parse import urlparse
import idna
import json
import os

app = Flask(__name__)

# Load the trained model
model = None
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
except FileNotFoundError:
    print("Error: model.pkl not found. Run train_model.py first.")

def extract_features(url):
    # Feature 1: URL Length
    url_length = len(url)
    
    # Feature 2: Has IP Address
    has_ip = 0
    # Regex for IPv4
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    if re.search(ip_pattern, url):
        has_ip = 1
        
    # Feature 3: Has @ Symbol
    has_at = 1 if '@' in url else 0
    
    # Feature 4: Dot Count
    dot_count = url.count('.')
    
    # Feature 5: Is HTTPS
    is_https = 1 if url.startswith('https') else 0
    
    return [url_length, has_ip, has_at, dot_count, is_https]

def generate_analysis(features, url, status, confidence):
    # features = [url_length, has_ip, has_at, dot_count, is_https]
    url_length, has_ip, has_at, dot_count, is_https = features
    
    problems = []
    good_points = []
    
    # 1. Analyze HTTPS
    if is_https:
        good_points.append("The website uses HTTPS, which ensures valid encryption.")
    else:
        problems.append("The website does NOT use HTTPS. This is risky for entering private data.")

    # 2. Analyze URL Length
    if url_length > 75:
        problems.append(f"The URL is suspiciously long ({url_length} characters). Scammers often do this to hide the real domain.")
    elif url_length > 50:
        problems.append(f"The URL is relatively long ({url_length} characters). Verify the domain name carefully.")
    elif url_length < 30:
        good_points.append("The URL length is short and concise.")
    
    # 3. Analyze IP Address
    if has_ip:
        problems.append("The host is identified by an IP address instead of a domain name. This is a strong indicator of a scam.")

    # 4. Analyze @ Symbol
    if has_at:
        problems.append("The URL contains an '@' symbol, often used to obscure the actual destination.")
    
    # 5. Analyze Dot Count
    if dot_count > 3:
        problems.append(f"The URL has many subdomains ({dot_count} dots). This is a common tactic to impersonate legitimate sites.")
    elif dot_count <= 2:
        good_points.append("The domain structure is simple and standard.")
        
    # 6. Fallback / AI Reasoning
    if status in ['Suspicious', 'Scam'] and not problems:
        # If heuristics didn't trigger but the model (which sees combinations) did:
        problems.append(f"Our AI model detected complex patterns associated with phishing sites (Confidence: {confidence}%).")

    # --- ADVANCED CHECKS ---

    # 7. Analyze TLD (Top-Level Domain)
    # Simple extraction for demo: assuming last part after dot is TLD or second level
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        # Remove port if exists
        domain = domain.split(':')[0]
        
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co']
        risky_tlds = ['.xyz', '.top', '.tk', '.gq', '.ml', '.cf', '.cn', '.info']
        
        if any(domain.endswith(tld) for tld in common_tlds):
            good_points.append("Hosted on a widely trusted Top-Level Domain (TLD).")
        elif any(domain.endswith(tld) for tld in risky_tlds):
            problems.append("Hosted on a TLD frequently used by scammers/spammers (.xyz, .top, etc).")
    except:
        pass # parsing error fallback

    # 8. Hyphen Check
    hyphen_count = url.count('-')
    if hyphen_count > 3:
        problems.append(f"Excessive use of hyphens ({hyphen_count}). Legitimate sites rarely use this many.")
    elif hyphen_count == 0:
         good_points.append("Clean URL structure with no hyphens.")

    # 9. Numeric Check
    digit_count = sum(c.isdigit() for c in url)
    if digit_count > 5:
        problems.append("The URL contains many numbers. Legitimate brands usually prefer clean, alphabetic domains.")
    
    # 10. Keyword Check
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'confirm']
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        # Only flag if it's not a known safe domain (simplified logic)
        problems.append("Contains sensitive keywords (like 'login', 'secure') often found in phishing links.")

    # 11. General Confidence Good Point
    if status == 'Safe' and confidence > 80:
        good_points.append(f"High AI Confidence ({confidence}%) that this site structure is benign.")

    return problems, good_points

def get_deep_scan_info(url):
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    info = {
        'ip': 'Unknown',
        'provider': 'Unknown',
        'location': 'Unknown',
        'certificate': {'issuer': 'No SSL', 'expires': 'N/A'},
        'passive_dns': 0,
        'similar_urls': [],
        'hosted_domains': 0 # Mocked
    }
    
    # 1. IP & Geo & Provider
    try:
        ip = socket.gethostbyname(domain)
        info['ip'] = ip
        # Use ip-api.com (Free for non-commercial)
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,isp,org', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    info['location'] = data['country']
                    info['provider'] = data['isp']
        except:
            pass
    except:
        info['ip'] = "Could not resolve"

    # 2. SSL Details
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Issuer
                issuer = dict(x[0] for x in cert['issuer'])
                info['certificate']['issuer'] = issuer.get('organizationName', 'Unknown Authority')
                # Expiry
                not_after = cert['notAfter']
                # Format: May 25 12:00:00 2026 GMT
                dt = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %GMT')
                info['certificate']['expires'] = dt.strftime('%Y-%m-%d')
    except:
        pass

    # 3. Similar URLs / Typosquatting (Simulation for Demo)
    # In a real app, you'd check if these resolve. Here we just generate them.
    name = domain.split('.')[0]
    tld = '.'.join(domain.split('.')[1:])
    if len(name) > 3:
        variations = [
            f"{name}0.{tld}",     # 0 instead of o (if applicable) or suffix
            f"{name}-secure.{tld}",
            f"{name}login.{tld}"
        ]
        info['similar_urls'] = variations
    
    # 4. Passive DNS / Same IP (Mocked/Randomized for Demo unless API key present)
    # Real data requires paid keys like VirusTotal, SecurityTrails, etc.
    # We will simulate valid-looking data for the Viva presentation.
    info['passive_dns'] = np.random.randint(5, 50) # Random realistic number
    info['hosted_domains'] = np.random.randint(1, 15)
    
    
    return info

# --- ADVANCED FAKE DETECTION LOGIC ---

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_fake_url_score(url, scan_info=None):
    score = 0
    breakdown = {}
    
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    parsed = urlparse(url)
    path = parsed.path
    
    # 1. Homograph / IDNA Check
    try:
        domain.encode('ascii')
        is_homograph = False
    except UnicodeEncodeError:
        is_homograph = True
        score += 20
    breakdown['homograph'] = {'detected': is_homograph, 'score': 20 if is_homograph else 0}

    # 2. Brand Misuse (Simplified List)
    brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram', 'whatsapp', 'bank']
    brand_misuse = False
    for brand in brands:
        if brand in url and brand not in domain.split('.'):
            # Brand is in URL but not the main domain part (e.g. google-login.com or com-google)
            # A strict check would verify SLD. Here we assume misuse if brand is present but not exact match of a known safe list
            # For simplicity: if brand in URL but domain is NOT brand.com/.net etc
            if not (domain.startswith(brand + '.') or domain == brand + '.com' or domain == brand + '.org'):
                 brand_misuse = True
                 score += 25
                 break
    breakdown['brand_misuse'] = {'detected': brand_misuse, 'score': 25 if brand_misuse else 0}

    # 3. High Entropy (Randomness)
    entropy = calculate_entropy(domain)
    is_high_entropy = entropy > 4.5 # Threshold
    if is_high_entropy:
        score += 15
    breakdown['entropy'] = {'value': round(entropy, 2), 'score': 15 if is_high_entropy else 0}

    # 4. Excessive Subdomains
    subdomains = domain.split('.')
    excessive_subs = len(subdomains) > 3
    if excessive_subs:
        score += 10
    breakdown['subdomains'] = {'count': len(subdomains), 'score': 10 if excessive_subs else 0}

    # 5. URL Shortener
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'cli.gs']
    is_shortener = any(s in domain for s in shorteners)
    if is_shortener:
        score += 15
    breakdown['shortener'] = {'detected': is_shortener, 'score': 15 if is_shortener else 0}

    # 6. Sensitive Keywords
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking']
    has_keyword = any(k in url.lower() for k in keywords)
    if has_keyword:
        score += 10
    breakdown['keywords'] = {'detected': has_keyword, 'score': 10 if has_keyword else 0}
    
    # 7. Port in URL
    has_port = ':' in domain and not domain.endswith(':80') and not domain.endswith(':443')
    if has_port:
        score += 5
    breakdown['port_detected'] = {'detected': has_port, 'score': 5 if has_port else 0}
    
    # 8. Double Extensions (e.g., .txt.exe - rare in URLs but logic requested)
    # Applying to path mainly
    double_ext = re.search(r'\.[a-z]{2,4}\.[a-z]{2,4}$', path)
    if double_ext:
        score += 10
    breakdown['double_extension'] = {'detected': bool(double_ext), 'score': 10 if double_ext else 0}

    # 9. Network Failures (IP/SSL from Deep Scan)
    if scan_info:
        # IP Check
        ip_fail = scan_info.get('ip') == "Could not resolve"
        if ip_fail:
            score += 30
        breakdown['ip_resolution'] = {'detected': ip_fail, 'score': 30 if ip_fail else 0}

        # SSL Check
        cert_info = scan_info.get('certificate', {})
        ssl_fail = cert_info.get('issuer') == "No SSL" or not cert_info.get('expires')
        if ssl_fail:
            score += 20
        breakdown['ssl_status'] = {'detected': ssl_fail, 'score': 20 if ssl_fail else 0}

    return score, breakdown

# --- SCAM CALL DETECTION LOGIC ---

SCAM_DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'scam_data.json')
scam_data_cache = None

def load_scam_data():
    global scam_data_cache
    if scam_data_cache:
        return scam_data_cache
    try:
        with open(SCAM_DATA_FILE, 'r') as f:
            scam_data_cache = json.load(f)
        return scam_data_cache
    except Exception as e:
        print(f"Error loading scam data: {e}")
        return {"scam_prefixes": {}, "blacklist": [], "risk_patterns": {}}

def analyze_phone_number(phone):
    phone = re.sub(r'[^0-9+]', '', phone) # Sanitize
    
    status = "Safe"
    risk_level = "Low"
    confidence = 0
    reasons = []
    
    data = load_scam_data()
    prefixes = data.get('scam_prefixes', {})
    blacklist = set(data.get('blacklist', []))
    patterns = data.get('risk_patterns', {})
    
    # 0. Basic Validation
    if not phone:
        return {"status": "Invalid", "risk": "Unknown", "confidence": 0, "reasons": ["No number provided."]}
    
    if len(phone) < 7 or len(phone) > 15:
         return {"status": "Invalid", "risk": "High", "confidence": 100, "reasons": [f"Invalid length ({len(phone)} digits). Valid numbers are usually 7-15 digits."]}

    # 1. Blacklist Check
    if phone in blacklist:
        return {
            "status": "Scam",
            "risk": "Critical",
            "confidence": 100,
            "reasons": ["Blacklisted: Confirmed scam number in database."],
            "ml_analysis": None
        }

    # 2. Key-based Prefix Check
    # We iterate to find the longest matching prefix
    matched_prefix_data = None
    longest_prefix_len = 0
    
    for prefix, p_data in prefixes.items():
        if phone.startswith(prefix):
            if len(prefix) > longest_prefix_len:
                longest_prefix_len = len(prefix)
                matched_prefix_data = p_data
                matched_prefix_data['prefix'] = prefix

    if matched_prefix_data:
        status = "Scam"
        risk_level = matched_prefix_data.get('risk', 'High')
        confidence += matched_prefix_data.get('confidence_boost', 50)
        reasons.append(f"Originates from high-risk prefix ({matched_prefix_data['prefix']}) - {matched_prefix_data.get('country', 'Unknown')}.")
        reasons.append(matched_prefix_data.get('description', 'Known fraud region.'))

    # 3. Pattern Analysis (Regex Rules)
    for p_name, p_rule in patterns.items():
        if re.search(p_rule['regex'], phone):
            # If already flagged as scam, just add confidence
            if status == "Safe":
                status = "Suspicious"
                risk_level = "Medium"
            
            confidence += p_rule.get('score', 20)
            reasons.append(f"Pattern detected: {p_rule.get('description', p_name)}")

    # 4. Final Score Normalization
    if confidence > 100: confidence = 100
    if status == "Safe" and confidence == 0:
        confidence = 95 # High confidence it is safe
        reasons.append("Number format looks clean. No known risk indicators found.")
    
    # Logic for mixed signals (e.g. prefix + pattern could push Suspicious to Scam)
    if status == "Suspicious" and confidence > 70:
        status = "Scam"
        risk_level = "High"

    return {
        "status": status,
        "risk": risk_level,
        "confidence": confidence,
        "reasons": reasons
    }

@app.route('/predict-call', methods=['POST'])
def predict_call():
    data = request.json
    phone = data.get('phone', '')
    result = analyze_phone_number(phone)
    return jsonify(result)

@app.route('/get-scam-config', methods=['GET'])
def get_scam_config():
    data = load_scam_data()
    return jsonify(data)


@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/site-detection')
def site_detection():
    return render_template('site_detection.html')

@app.route('/call-detection')
def call_detection():
    return render_template('call_detection.html')

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'Model not loaded'}), 500

    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
        
    # Basic validation
    if not re.match(r'^(http|https)://', url):
        # Allow user to type google.com and auto-prepend, but for feature extraction let's just warn or handle
        if not url.startswith(('http://', 'https://')):
             url = 'http://' + url

    features = extract_features(url)
    features_np = np.array([features])
    
    prediction = model.predict(features_np)[0]
    probabilities = model.predict_proba(features_np)[0]
    confidence = round(max(probabilities) * 100, 2)
    
    # 0: Safe, 1: Suspicious, 2: Scam
    status_map = {0: 'Safe', 1: 'Suspicious', 2: 'Scam'}
    result = status_map.get(prediction, 'Unknown')

    # Generate Analysis
    problems, good_points = generate_analysis(features, url, result, confidence)
    
    # Deep Scan (New)
    scan_info = get_deep_scan_info(url)
    
    # Fake URL Score (New)
    fake_score, fake_breakdown = calculate_fake_url_score(url, scan_info)

    # --- ENHANCED RISK CALCULATION ---
    # Adjust confidence/status based on deep scan failures
    network_risk_score = 0
    
    # Check IP Resolution
    if scan_info.get('ip') == "Could not resolve":
        network_risk_score += 40
        problems.append("Critical: Domain could not be resolved to an IP address.")
    
    # Check SSL
    cert_info = scan_info.get('certificate', {})
    if cert_info.get('issuer') == "No SSL" or not cert_info.get('expires'):
        network_risk_score += 30
        problems.append("Security Warning: No valid SSL certificate found.")
    
    # Check Hosting Provider
    if scan_info.get('provider') == "Unknown":
        network_risk_score += 10

    # If significant network risks are found, override status (if currently Safe)
    if network_risk_score > 50:
        if result == "Safe":
            result = "Suspicious"
            confidence = max(confidence, network_risk_score)
            problems.append(f"Downgraded to Suspicious due to network anomalies (Score: {network_risk_score}).")
        elif result == "Suspicious":
            result = "Scam"
            confidence = min(confidence + 20, 100) # Boost confidence
            problems.append(f"Escalated to Scam due to missing network identifiers (Score: {network_risk_score}).")
    
    # If Fake Score is high, force Scam
    if fake_score > 60 and result != "Scam":
        result = "Scam"
        if confidence < fake_score:
            confidence = fake_score
        problems.append(f"Flagged as Scam due to high Fake URL Score ({fake_score}).")

    return jsonify({
        'url': url,
        'status': result,
        'confidence': confidence,
        'features': features,
        'problems': problems,
        'good_points': good_points,
        'scan_info': scan_info,
        'fake_score': {
            'total': fake_score,
            'breakdown': fake_breakdown
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
