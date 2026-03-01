import re
from urllib.parse import urlparse

def extract_features(url: str):
    """Extracts lexical and structural features from a URL."""
    try:
        parsed_url = urlparse(url)
    except:
        parsed_url = None

    features = {
        "length": len(url),
        "has_at_symbol": "@" in url,
        "has_hyphen_in_domain": "-" in parsed_url.netloc if parsed_url else False,
        "is_ip_address": is_ip(parsed_url.netloc) if parsed_url else False,
        "suspicious_keywords": count_suspicious_keywords(url),
        "subdomain_count": count_subdomains(parsed_url.netloc) if parsed_url else 0,
        "protocol": parsed_url.scheme if parsed_url else "unknown"
    }
    return features

def is_ip(domain: str) -> bool:
    """Checks if the domain is an IP address."""
    # Simple regex for IPv4
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return bool(ip_pattern.match(domain))

def count_suspicious_keywords(url: str) -> int:
    """Counts the occurrences of common phishing keywords in the URL."""
    keywords = ["login", "bank", "secure", "verify", "update", "account", "paypal", "free", "admin"]
    url_lower = url.lower()
    return sum(1 for keyword in keywords if keyword in url_lower)

def count_subdomains(domain: str) -> int:
    """Estimates the number of subdomains."""
    if not domain:
        return 0
    # Remove port if present
    domain = domain.split(':')[0]
    parts = domain.split('.')
    # Assume last two parts are SLD and TLD (e.g., example.com)
    # This is a naive approximation; a robust solution uses Public Suffix List
    return max(0, len(parts) - 2)

def calculate_risk_score(features: dict) -> dict:
    """
    Calculates a naive risk score based on the extracted features.
    In a real app, this would be replaced by an ML model and API calls.
    """
    score = 0
    reasons = []

    if features["has_at_symbol"]:
        score += 30
        reasons.append("URL contains '@' symbol, often used to obfuscate the real domain.")
    
    if features["has_hyphen_in_domain"]:
        score += 10
        reasons.append("Domain contains a hyphen, which is common in phishing sites.")

    if features["is_ip_address"]:
        score += 50
        reasons.append("Domain is an IP address instead of a standard hostname.")

    if features["suspicious_keywords"] > 0:
        score += 20 * features["suspicious_keywords"]
        reasons.append(f"URL contains {features['suspicious_keywords']} suspicious keywords (e.g., 'login', 'secure').")
    
    if features["subdomain_count"] > 2:
        score += 20
        reasons.append("Unusually high number of subdomains detected.")
    
    if features["protocol"] != "https":
        score += 15
        reasons.append("URL does not use secure HTTPS protocol.")

    # Cap at 100
    final_score = min(100, score)
    
    threat_level = "Safe"
    if final_score > 60:
        threat_level = "Malicious"
    elif final_score > 30:
        threat_level = "Suspicious"

    return {
        "risk_score": final_score,
        "threat_level": threat_level,
        "reasons": reasons
    }

if __name__ == "__main__":
    # Test cases
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "https://secure-update.paypal.com-verify.info"
    ]
    for test in test_urls:
        print(f"URL: {test}")
        feats = extract_features(test)
        print(f"Score: {calculate_risk_score(feats)}")
        print("-" * 20)
