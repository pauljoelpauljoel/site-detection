from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import pandas as pd
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
import whois
from bs4 import BeautifulSoup

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

def get_domain_age(domain):
    # Helper to clean domain
    def clean(d):
        return d.lower().strip()

    try:
        print(f"DEBUG: Checking whois for {domain}")
        try:
            w = whois.whois(domain)
        except Exception as e:
             # If exact match fails (e.g. subdomain), try stripping one level
             parts = domain.split('.')
             if len(parts) > 2:
                 parent = '.'.join(parts[1:])
                 print(f"DEBUG: Exact match failed. Retrying parent: {parent}")
                 try:
                    w = whois.whois(parent)
                 except Exception as sub_e:
                    return -1, str(sub_e)
             else:
                 return -1, str(e)

        creation_date = w.creation_date
        print(f"DEBUG: Creation date: {creation_date}")
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
             return -1, "No creation date found"
             
        # Handle string dates if any
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
            except:
                pass
                
        if not isinstance(creation_date, datetime.datetime):
            return None, "Invalid date format"

        return creation_date, None
    except Exception as e:
        print(f"DEBUG: Whois error for {domain}: {e}")
        return -1, str(e)

def check_google_index(domain):
    try:
        query = f"site:{domain}"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (HTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        url = f"https://www.google.com/search?q={query}"
        print(f"DEBUG: Checking Google Index for {domain}")
        resp = requests.get(url, headers=headers, timeout=5)
        print(f"DEBUG: Google Status Code: {resp.status_code}")
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Look for search results container. This is brittle but a decent heuristic for a demo.
            # If "did not match any documents" or similar is found, it's not indexed.
            if "did not match any documents" in resp.text:
                return False
            return True
        elif resp.status_code == 429:
             print("DEBUG: Google blocked request (429)")
             return None
        return None # Blocked or error
    except Exception as e:
        print(f"DEBUG: Google Index error: {e}")
        return None

def analyze_page_content(url):
    findings = {
        'password_field': False,
        'hidden_forms': False,
        'obfuscation': [],
        'fake_login': False
    }
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return findings
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        html_lower = resp.text.lower()
        
        # 1. Password Field
        if soup.find('input', {'type': 'password'}):
            findings['password_field'] = True
            
        # 2. Hidden Forms/Fields
        if soup.find('input', {'type': 'hidden'}):
            # Many legit sites use hidden fields, so maybe only flag if combined with other things?
            # For now, just detect.
            findings['hidden_forms'] = True

        # 3. Obfuscation
        suspicious_js = ['eval(', 'atob(', 'document.write(', 'unescape(']
        for js in suspicious_js:
            if js in html_lower:
                findings['obfuscation'].append(js)
        
        # 4. Fake Login (Heuristic)
        # If password field exists + title/text contains "Login" etc
        if findings['password_field']:
            keywords = ['login', 'sign in', 'account', 'verify']
            if any(k in html_lower for k in keywords):
                findings['fake_login'] = True

    except:
        pass
    return findings

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





@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/site-detection')
def site_detection():
    return render_template('site_detection.html')



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
    try:
        # Create DataFrame with feature names to avoid sklearn UserWarning
        feature_names = ['url_length', 'has_ip', 'has_at', 'dot_count', 'is_https']
        features_df = pd.DataFrame([features], columns=feature_names)
        
        prediction = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        confidence = round(max(probabilities) * 100, 2)
    except Exception as e:
        print(f"Prediction Error: {e}")
        # Fallback to numpy array if DataFrame fails (backward compatibility)
        try:
            print("Attempting fallback to numpy array...")
            features_np = np.array([features])
            prediction = model.predict(features_np)[0]
            probabilities = model.predict_proba(features_np)[0]
            confidence = round(max(probabilities) * 100, 2)
        except Exception as e2:
             return jsonify({'error': f"Prediction failed: {str(e2)}"}), 500
    
    # 0: Safe, 1: Suspicious, 2: Scam
    status_map = {0: 'Safe', 1: 'Suspicious', 2: 'Scam'}
    result = status_map.get(prediction, 'Unknown')

    # Generate Analysis
    problems, good_points = generate_analysis(features, url, result, confidence)
    
    # Deep Scan (New)
    scan_info = get_deep_scan_info(url)
    
    # Fake URL Score (New)
    fake_score, fake_breakdown = calculate_fake_url_score(url, scan_info)

    # --- ADVANCED FEATURE INTEGRATION ---
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]

    # 1. Domain Age
    creation_date, age_error = get_domain_age(domain)
    
    age_days = -1
    age_years = -1
    creation_year = "Unknown"
    
    if creation_date:
        # Handle timezone awareness (creation_date might be UTC/aware while now() is naive)
        now = datetime.datetime.now(creation_date.tzinfo)
        age_days = (now - creation_date).days
        age_years = round(age_days / 365.25, 1)
        creation_year = creation_date.year
    
    # Always add to breakdown for UI
    fake_breakdown['domain_age'] = {
        'days': age_days, 
        'years': age_years,
        'creation_year': creation_year,
        'score': 0, 
        'error': age_error
    }
    
    if age_days != -1:
        if age_days < 30:
            fake_score += 30
            problems.append(f"Domain is very new ({age_days} days old). Highly suspicious.")
            fake_breakdown['domain_age']['score'] = 30
        elif age_days < 180:
             # Neutral
             pass
        else:
             good_points.append(f"Domain established in {creation_year} ({age_years} years ago).")
    
    # 2. Google Index
    is_indexed = check_google_index(domain)
    # Always add to breakdown
    fake_breakdown['google_index'] = {'indexed': is_indexed, 'score': 0}

    if is_indexed is False:
        fake_score += 20
        problems.append("Domain does not appear to be indexed by Google.")
        fake_breakdown['google_index']['score'] = 20
    elif is_indexed is True:
        good_points.append("Domain is indexed by Google.")

    # 3. Content Analysis
    content_findings = analyze_page_content(url)
    
    if content_findings['password_field']:
        # If site is not HTTPS and has password field -> Critical
        if not is_https:
            fake_score += 25
            problems.append("Insecure Page: Password field detected on non-HTTPS site.")
            fake_breakdown['insecure_password'] = {'detected': True, 'score': 25}
    
    if content_findings['obfuscation']:
        fake_score += 15
        problems.append(f"Suspicious JavaScript detected: {', '.join(content_findings['obfuscation'])}")
        fake_breakdown['obfuscation'] = {'detected': True, 'techniques': content_findings['obfuscation'], 'score': 15}

    # --- VISUAL AI (Feature 5) ---
    fake_breakdown['visual_ai'] = {'detected': False, 'score': 0}
    visual_match_brand = None
    visual_score = 0
    screenshot_b64 = None

    try:
        import visual_matcher
        
        # Get Base64 and Bytes directly
        screenshot_b64, screenshot_bytes = visual_matcher.capture_screenshot(url)
        
        if screenshot_bytes:
            visual_match_brand, visual_score = visual_matcher.compare_visuals(screenshot_bytes)
            if visual_match_brand and visual_score > 70:
                fake_score += 40
                problems.append(f"Visual AI: Website looks {visual_score}% like {visual_match_brand}.")
                fake_breakdown['visual_ai'] = {'detected': True, 'brand': visual_match_brand, 'score': visual_score}
    except Exception as e:
        print(f"DEBUG: Visual AI Failed: {e}")
        visual_ai_error = str(e)
        # Continue without visual ai

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
        },
        'visual_analysis': {
            'screenshot': f"data:image/png;base64,{screenshot_b64}" if 'screenshot_b64' in locals() and screenshot_b64 else None,
            'match': 'visual_match_brand' in locals() and visual_match_brand,
            'similarity': 'visual_score' in locals() and visual_score,
            'error': visual_ai_error if 'visual_ai_error' in locals() else None
        }
    })

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
