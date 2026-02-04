
import visual_matcher
import os

print("Testing Visual Matcher Isolation...")
try:
    # Test with a simple known URL
    filename = visual_matcher.capture_screenshot("https://example.com", "test_capture.png")
    
    if filename:
        print(f"SUCCESS: Screenshot saved as {filename}")
        # Cleanup
        path = os.path.join(visual_matcher.TEMP_DIR, filename)
        if os.path.exists(path):
            print(f"File exists at {path}")
            # os.remove(path) 
    else:
        print("FAILURE: capture_screenshot returned None")

except Exception as e:
    print(f"CRITICAL EXCEPTION: {e}")
    import traceback
    traceback.print_exc()
