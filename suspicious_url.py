import re
import difflib

suspicious_tld = ['.tk', '.buzz', '.xyz', '.top', '.ga', '.ml', '.info', '.cf', '.online', '.live', '.ru']
legit_domains = ["google.com", "paypal.com", "microsoft.com", "amazon.com", "netflix.com", "apple.com", "facebook.com"]

def is_http(url):
    if re.match(r"^http://", url): #^ == front of string
        return True
    return False

def is_ip_address(url):
    clean_url = url.removeprefix("https://").removeprefix("http://")
    if re.match(r"\d+\.\d+\.\d+\.\d+", clean_url): #\d == digits (0-9), \. == followed by a period, + == one or more
        return True
    return False
    
def has_suspicious_tld(url):
    for each in suspicious_tld:
        if url.endswith(each):
            return True
        
    return False

def many_subdomain(url):
    period_count = url.count(".")
    if period_count >= 4:
        return True
    return False

def typosquat(url):
    clean_url = url.removeprefix("https://").removeprefix("http://") #if no prefix, this line is arbitrary
    for each in legit_domains:
        ratio = difflib.SequenceMatcher(None, clean_url, each).ratio()
        if ratio > 0.75:
            return True
    
    return False

def has_redirect(url):
    if re.match("redirect", url):
        return True
    return False

def main():
    print("This URL detector was developed by a student for educational purposes. Use with caution and do not rely on it for critical decisions.")
    print("====================")
    url = input("Enter URL: ")
    checks = [is_http(url), is_ip_address(url), has_suspicious_tld(url), many_subdomain(url), typosquat(url), has_redirect(url)]
    
    if any(checks):
        print("Suspicious URL detected.")
    else:
        print("URL appears safe.")
        
if __name__ == "__main__":
    main() 



