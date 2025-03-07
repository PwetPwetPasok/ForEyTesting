from flask import Flask, render_template, request, Response
import requests
import base64
import os
import whois
import logging
import subprocess
from dotenv import load_dotenv
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from analysis.analyzer import analyze_url


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Retrieve API keys from environment variables
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
TWITTER_BEARER_TOKEN = os.getenv('TWITTER_BEARER_TOKEN')
SCREENSHOT_API_KEY = os.getenv('SCREENSHOT_API_KEY')

if not API_KEY:
    raise ValueError("VirusTotal API key is not set in environment variables.")
if not TWITTER_BEARER_TOKEN:
    raise ValueError("Twitter Bearer Token is not set in environment variables.")
if not SCREENSHOT_API_KEY:
    raise ValueError("Screenshot API key is not set in environment variables.")

VT_URL = 'http://www.virustotal.com/api/v3/urls'
SCREENSHOT_URL = 'https://api.screenshotapi.net/screenshot'
logging.basicConfig(level=logging.DEBUG)

def normalize_url(url):
    """Remove the protocol from the URL if it exists."""
    if '://' in url:
        return url.split('://', 1)[-1]
    return url

def format_detection_results(malicious_count, total_scans):
    """Format the detection result message."""
    return f"{malicious_count}/{total_scans}"

def get_virus_total_report(url):
    headers = {'x-apikey': API_KEY}
    
    # Ensure the URL includes the protocol (http or https)
    if not urlparse(url).scheme:
        url = 'http://' + url

    # URL Encoding based on VirusTotal requirements
    url_id = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip('=')
    
    try:
        # Attempt to retrieve the report from VirusTotal
        response = requests.get(f'{VT_URL}/{url_id}', headers=headers)
        data = response.json()
        
        if 'error' in data and data['error'].get('code') == 'NotFoundError':
            # If the URL is not found, submit it for analysis
            submission_response = requests.post(VT_URL, headers=headers, data={'url': url})
            submission_data = submission_response.json()

            if 'error' in submission_data:
                return {'error': f"Error submitting URL for analysis: {submission_data['error'].get('message', 'Unknown error occurred')}"}

            # Extract the id for the submitted URL
            submission_id = submission_data.get('data', {}).get('id')
            if not submission_id:
                return {'error': 'Error retrieving submission ID'}

            # Attempt to retrieve the report again using the submission id
            response = requests.get(f'{VT_URL}/{submission_id}', headers=headers)
            data = response.json()

        if 'error' in data:
            error_message = data['error'].get('message', 'Unknown error occurred')
            return {'error': error_message}
        
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        total_scans = stats.get('total', 0)
        scan_results = attributes.get('last_analysis_results', {})
        categories = attributes.get('categories', {})

        # Format the detection result message
        detection_message = format_detection_results(malicious_count, total_scans)
        
        # Top malicious vendors
        top_malicious_vendors = {
            vendor: info['result']
            for vendor, info in sorted(
                scan_results.items(),
                key=lambda x: x[1]['result'] == 'malicious',
                reverse=True
            )[:10]
        }
        
        # Community comments
        community_comments = attributes.get('community_reviews', [])
        if not community_comments:
            community_comments = ['No community reviews available']
        
        # Relations
        relations = attributes.get('relations', {})
        subdomains = relations.get('subdomains', [])
        urls = relations.get('urls', [])
        communicating_files = relations.get('communicating_files', [])
        
        if not subdomains:
            subdomains = ['No subdomains found']
        if not urls:
            urls = ['No URLs found']
        if not communicating_files:
            communicating_files = ['No communicating files found']
        
        # Categories
        suggested_category = categories.get('suggested', 'N/A')
        all_categories = ', '.join(f'{key}: {value}' for key, value in categories.items())
        
        # Return the analysis results
        return {
            'url': url,
            'detection_message': detection_message,
            'vendor_analysis': top_malicious_vendors,
            'community_comments': community_comments,
            'subdomains': subdomains,
            'urls': urls,
            'communicating_files': communicating_files,
            'suggested_category': suggested_category,
            'all_categories': all_categories
        }
    
    except Exception as e:
        return {'error': f"Error fetching VirusTotal report: {str(e)}"}

def rewrite_html(html_content, original_url):

    # Ensure the content is in UTF-8 encoding
    html_content = html_content.decode('utf-8', 'replace')

    soup = BeautifulSoup(html_content, 'html.parser')
    base_url = urlparse(original_url)._replace(path='').geturl()  # Extract base URL

    # Rewrite links
    for link in soup.find_all('a', href=True):
        link['href'] = urljoin(base_url, link['href'])

    # Rewrite images
    for img in soup.find_all('img', src=True):
        img['src'] = urljoin(base_url, img['src'])

    # Rewrite CSS and JavaScript links
    for link in soup.find_all('link', href=True):
        if link.get('rel') == ['stylesheet']:
            link['href'] = urljoin(base_url, link['href'])
    for script in soup.find_all('script', src=True):
        script['src'] = urljoin(base_url, script['src'])

    return str(soup)

def get_screenshot(url):
    try:
        params = {
            'key': SCREENSHOT_API_KEY,
            'url': url,
            'output': 'json',
            'fresh': 'true'
        }
        response = requests.get(SCREENSHOT_URL, params=params)
        data = response.json()
        screenshot_url = data.get('screenshot', {}).get('url', '')
        return screenshot_url if screenshot_url else 'No screenshot available'
    except Exception as e:
        return f"Error fetching screenshot: {str(e)}"

def format_date(date):
    """Format datetime object to 'YYYY-MM-DD'."""
    if isinstance(date, datetime):
        return date.strftime('%Y-%m-%d')
    return 'N/A'

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        result = {
            'domain': domain,
            'registrar': domain_info.registrar,
            'creation_date': format_date(domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date),
            'expiration_date': format_date(domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date),
            'name_servers': domain_info.name_servers,
            'org': domain_info.get('org', 'N/A'),
            'state': domain_info.get('state', 'N/A'),
            'country': domain_info.get('country', 'N/A')
        }
        return result
    except Exception as e:
        return {'error': f"Error fetching WHOIS information: {str(e)}"}

    
@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    if not url:
        return "Please provide a URL."

    method = request.method
    headers = {key: value for key, value in request.headers if key != 'Host'}

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=request.args, allow_redirects=True)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=request.form, params=request.args, allow_redirects=True)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, data=request.data, params=request.args, allow_redirects=True)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, params=request.args, allow_redirects=True)
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, data=request.data, params=request.args, allow_redirects=True)
        elif method == 'HEAD':
            response = requests.head(url, headers=headers, params=request.args, allow_redirects=True)
        else:
            return "Method not allowed.", 405

        content_type = response.headers.get('Content-Type', '')

        # Process and return the response based on content type
        if 'text/html' in content_type:
            response.encoding = response.apparent_encoding
            rewritten_content = rewrite_html(response.content, url)
            return Response(rewritten_content, status=response.status_code, content_type='text/html')
        elif 'application/json' in content_type:
            return Response(response.content, status=response.status_code, content_type='application/json')
        elif 'application/xml' in content_type:
            return Response(response.content, status=response.status_code, content_type='application/xml')
        else:
            return Response(response.content, status=response.status_code, content_type=content_type)
    except requests.RequestException as e:
        logging.error(f"Request error: {str(e)}")
        return f"Request error: {str(e)}", 500

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    whois_result = None
    screenshot_url = None
    urlscan_url = None
    google_url = None
    proxy_url = None
    analysis_result = None
    monitor_url = None

    if request.method == 'POST':
        url = request.form.get('url')
        
        if url:
            try:
                # Perform URL analysis
                analysis_result = analyze_url(url)

                # Get VirusTotal report for the original URL
                result = get_virus_total_report(url)
                
                # Extract domain and get Whois info using the original URL
                parsed_url = urlparse(url)
                domain = parsed_url.netloc or parsed_url.path
                if not domain:
                    raise ValueError("Invalid URL format.")
                whois_result = get_whois_info(domain)

                # Get screenshot of the URL
                screenshot_url = get_screenshot(url)

                # Construct URLScan.io search URL
                urlscan_url = f'https://urlscan.io/search/#{normalize_url(url)}'
                
                # Normalize the query by removing protocol if present
                normalized_query = normalize_url(url)

                # Construct Google and Twitter search URLs
                google_url = f'https://www.google.com/search?q={normalized_query}'
                

            except Exception as e:
                result = {'error': str(e)}
    
    if request.method == 'GET' and request.args.get('url'):
        proxy_url = request.args.get('url')
    
    return render_template('index.html',monitor_url=monitor_url, result=result, whois_result=whois_result, screenshot_url=screenshot_url, urlscan_url=urlscan_url, google_url=google_url, proxy_url=proxy_url, analysis_result=analysis_result)

if __name__ == '__main__':
    app.run(debug=True)