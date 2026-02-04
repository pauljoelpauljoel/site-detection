import whois
import sys

domains = ['google.com', 'church-website-26q9.onrender.com', 'onrender.com']

for d in domains:
    print(f"--- Checking {d} ---")
    try:
        w = whois.whois(d)
        print(f"Success. Creation date: {w.creation_date}")
    except Exception as e:
        print(f"Error: {e}")
