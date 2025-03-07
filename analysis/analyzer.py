from datetime import datetime
import re
from difflib import SequenceMatcher

# List of known popular domains to compare against for typosquatting
KNOWN_DOMAINS = [
    'google.com', 'facebook.com', 'apple.com', 'amazon.com',
    'microsoft.com', 'twitter.com', 'instagram.com', 'youtube.com', 
    'whatsapp.com' , 'linkedin.com', 'yahoo.com', 'netflix.com', 'github.com',
    'paypal.com', 'adobe.com', 'dropbox.com'
]

def analyze_url(url):
    try:
        print(f"Analyzing URL: {url}")  # Debugging line

        # Extract domain from the URL
        domain = extract_domain(url)
        if not domain:
            raise ValueError("Extracted domain is empty")

        print(f"Extracted domain: {domain}")  # Debugging line

        # Check if the domain is in KNOWN_DOMAINS
        if domain in KNOWN_DOMAINS:
            return {
                'typosquatting': [],
                'domain_age': 'N/A',
                'domain_reputation': 'Safe',
                'malicious_percentage': 0,
                'result_category': 'Safe',
                'color': 'Green'
            }

        # Analyze domain for typosquatting and reputation
        analysis_result = {
            'typosquatting': detect_typosquatting(domain),
            'domain_age': get_domain_age(domain),
            'domain_reputation': check_domain_reputation(domain)
        }

        print(f"Analysis result: {analysis_result}")  # Debugging line

        # Check for older domains registered for more than 5 years with no malicious detection in VT
        if analysis_result['domain_age'] and analysis_result['domain_age'] > 5 and analysis_result['domain_reputation'] == 'Clean':
            return {
                'typosquatting': analysis_result['typosquatting'],
                'domain_age': analysis_result['domain_age'],
                'domain_reputation': 'Clean',
                'malicious_percentage': 0,
                'result_category': 'Safe',
                'color': 'Green'
            }

        # Calculate the malicious percentage based on the analysis
        if analysis_result['typosquatting']:
            if analysis_result['domain_age'] is not None and analysis_result['domain_age'] < 2:
                malicious_percentage = 70  # Higher likelihood of being dangerous
            else:
                malicious_percentage = 40  # Lower likelihood
        else:
            # General calculation based on domain age and reputation
            malicious_percentage = calculate_malicious_percentage(analysis_result)

        print(f"Malicious percentage: {malicious_percentage}")  # Debugging line

        # Determine the analysis result category
        result_category, color = categorize_result(malicious_percentage)
        print(f"Result category: {result_category}, Color: {color}")  # Debugging line

        # Add the summary to the result
        analysis_result['malicious_percentage'] = malicious_percentage
        analysis_result['result_category'] = result_category
        analysis_result['color'] = color

        return analysis_result

    except Exception as e:
        print(f"Error in analyze_url: {e}")  # Debugging line
        return {'error': str(e)}


def detect_typosquatting(domain):
    from app import get_whois_info  # Delayed import to avoid circular import issues
    similar_domains = []
    for known_domain in KNOWN_DOMAINS:
        similarity = SequenceMatcher(None, domain, known_domain).ratio()
        print(f"Comparing domain: {domain} with known domain: {known_domain}, Similarity: {similarity}")  # Debugging line
        if similarity > 0.8:  # 80% similarity threshold for typosquatting
            whois_info = get_whois_info(known_domain)
            print(f"WHOIS info for {known_domain}: {whois_info}")  # Debugging line
            similar_domains.append({
                'domain': domain,
                'mimics': known_domain,
                'similarity': similarity,
                'whois_info': whois_info
            })
    return similar_domains

def extract_domain(url):
    match = re.search(r'^(?:https?://)?(?:www\.)?([^/]+)', url)
    if match:
        domain = match.group(1)
        print(f"Extracted domain from URL: {domain}")  # Debugging line
        return domain
    print("No domain extracted from URL")  # Debugging line
    return ''


def get_domain_age(domain):
    from app import get_whois_info  # Delayed import to avoid circular import issues
    whois_info = get_whois_info(domain)
    print(f"WHOIS info for domain {domain}: {whois_info}")  # Debugging line
    if 'creation_date' in whois_info:
        creation_date = whois_info['creation_date']
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and creation_date != 'N/A':
            try:
                creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
                age = (datetime.now() - creation_date).days // 365
                print(f"Domain age for {domain}: {age} years")  # Debugging line
                return age
            except ValueError:
                print(f"Error parsing creation date for {domain}: {creation_date}")  # Debugging line
                return None
    return None

def calculate_malicious_percentage(analysis_result):
    weights = {
        'typosquatting': 20,
        'domain_age': 20,
        'domain_reputation': 30
    }
    
    total_score = 0
    if analysis_result['typosquatting']:
        total_score += weights['typosquatting']
        print(f"Added typosquatting weight: {weights['typosquatting']}")  # Debugging line
    if analysis_result['domain_age'] is not None and analysis_result['domain_age'] < 2:
        total_score += weights['domain_age']
        print(f"Added domain age weight: {weights['domain_age']}")  # Debugging line
    if analysis_result['domain_reputation']:
        total_score += weights['domain_reputation']
        print(f"Added domain reputation weight: {weights['domain_reputation']}")  # Debugging line
    
    print(f"Total score: {total_score}")  # Debugging line
    return total_score

def categorize_result(malicious_percentage):
    if malicious_percentage >= 75:
        return "Dangerous", "Red"
    elif malicious_percentage >= 50:
        return "Suspicious", "Yellow"
    elif malicious_percentage >= 25:
        return "Undecided", "Grey"
    else:
        return "Safe", "Green"

# Delayed imports to avoid circular import issues
from app import get_virus_total_report as check_domain_reputation
