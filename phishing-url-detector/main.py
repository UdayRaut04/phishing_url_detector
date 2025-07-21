import re
from urllib.parse import urlparse

# List of suspicious top-level domains
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']

def is_ip_address(url):
    return re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url)

def count_dots(url):
    return url.count('.')

def has_at_symbol(url):
    return '@' in url

def has_long_url(url):
    return len(url) > 75

def has_suspicious_tld(url):
    parsed = urlparse(url)
    for tld in SUSPICIOUS_TLDS:
        if parsed.netloc.endswith(tld):
            return True
    return False

def check_url(url):
    print(f"\n🔍 Scanning URL: {url}")

    score = 0

    if is_ip_address(url):
        print("⚠️  Uses IP address instead of domain")
        score += 2
    if has_at_symbol(url):
        print("⚠️  Contains '@' symbol")
        score += 1
    if count_dots(url) > 5:
        print("⚠️  Too many dots (possible subdomain trick)")
        score += 1
    if has_long_url(url):
        print("⚠️  URL is very long")
        score += 1
    if has_suspicious_tld(url):
        print("⚠️  Suspicious top-level domain")
        score += 2

    # Final assessment
    if score == 0:
        print("✅ Safe URL")
    elif score <= 2:
        print("⚠️  Suspicious URL")
    else:
        print("❌ Potentially Malicious URL")

if __name__ == "__main__":
    url = input("Enter a URL to scan: ")
    check_url(url)
