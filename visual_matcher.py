import os
import imagehash
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

# Create matching directory if not exists
BRANDS_DIR = os.path.join(os.path.dirname(__file__), 'data', 'brands')
if not os.path.exists(BRANDS_DIR):
    os.makedirs(BRANDS_DIR)

import io
import base64

# Create matching directory if not exists
BRANDS_DIR = os.path.join(os.path.dirname(__file__), 'data', 'brands')
if not os.path.exists(BRANDS_DIR):
    os.makedirs(BRANDS_DIR)

# No TEMP_DIR needed for in-memory logic

def capture_screenshot(url):
    """
    Captures a screenshot of the URL using Headless Chrome.
    Returns (base64_str, image_bytes) or (None, None) if failed.
    """
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1280,720')
    options.add_argument('--log-level=3') # Silence logs

    driver = None
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        driver.set_page_load_timeout(15)
        driver.get(url)
        time.sleep(2) # Wait for render
        
        # Get screenshot as base64 string
        b64_data = driver.get_screenshot_as_base64()
        
        # Also get as bytes for imagehash
        png_data = driver.get_screenshot_as_png()
        
        print(f"DEBUG: Screenshot captured (Memory)")
        return b64_data, png_data
        
    except Exception as e:
        print(f"DEBUG: Screenshot failed: {e}")
        return None, None
    finally:
        if driver:
            driver.quit()

def compare_visuals(image_bytes):
    """
    Compares the captured screenshot bytes against known brand hashes.
    Returns (brand_name, score) where score is 0-100 similarity.
    """
    if not image_bytes:
        return None, 0

    try:
        # Load image from bytes
        img = Image.open(io.BytesIO(image_bytes))
        cap_hash = imagehash.phash(img)
        
        best_match = None
        min_diff = 100 # Threshold
        
        # Iterate over known brands
        for f in os.listdir(BRANDS_DIR):
            if f.endswith(('.png', '.jpg')):
                brand_path = os.path.join(BRANDS_DIR, f)
                brand_hash = imagehash.phash(Image.open(brand_path))
                
                # Hamlin distance: 0 = identical
                diff = cap_hash - brand_hash
                if diff < min_diff:
                    min_diff = diff
                    best_match = os.path.splitext(f)[0] # e.g. "google" from "google.png"

        # Normalize score (Diff 0 = 100%, Diff > 30 = 0%)
        if min_diff < 15: # Reasonable threshold for "Visually Similar"
             # Convert diff to percentage score roughly
             score = max(0, 100 - (min_diff * 4)) # 0 diff -> 100, 5 diff -> 80
             return best_match, score
        
        return None, 0

    except Exception as e:
        print(f"DEBUG: Visual comparison error: {e}")
        return None, 0
