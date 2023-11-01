import re
import unicodedata
import idna
import tldextract
import urllib.parse
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request

app = Flask(__name__)

# List of known malicious domains (you should use a more extensive list in practice)
malicious_domains = [
    "malicious1.com",
    "malicious2.org",
    "malicious3.net"
]

# Function to check if a URL is in the PhishTank database
def check_phishtank(url):
    try:
        # Construct the PhishTank URL for checking
        phishtank_url = f"https://checkurl.phishtank.com/checkurl/?url={urllib.parse.quote(url)}"

        # Send a GET request to PhishTank
        response = requests.get(phishtank_url)
        soup = BeautifulSoup(response.text, "html.parser")

        # Check if the URL is in the PhishTank database
        if "phish_detail.php" in str(soup):
            return "Potentially malicious (PhishTank)"
        else:
            return "Safe"
    except Exception as e:
        print("Error checking PhishTank:", str(e))
        return "Error"

# Function to check if a domain name uses non-Latin characters or Punycode
def check_domain_name(domain):
    # Convert to Unicode and normalize
    normalized_domain = idna.decode(domain)
    normalized_domain = unicodedata.normalize('NFKD', normalized_domain).encode('ASCII', 'ignore').decode('utf-8')

    # Check for non-Latin characters
    if normalized_domain != domain:
        return "Domain (potential spoofing)"

    if "xn--" in domain:
        return "Domain name uses Punycode (potential spoofing)"

    return "Domain name consists of Latin characters"

# Function to fetch the content of a URL
def fetch_url_content(url):

    try:
        # Prepend "http://" to the URL if it doesn't have a scheme
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url)
        return response.text
    except Exception as e:
        print("Error fetching URL content:", str(e))
        return None

# Function to check the script of a text
def check_script(text):
    scripts = set()
    for char in text:
        script = unicodedata.category(char)
        scripts.add(script)

    if len(scripts) > 1:
        return "Domain name uses multiple scripts"

    return "Domain name consists of a single script"
def get_script(character):
    try:
        name = unicodedata.name(character)
        return name.split()[0]
    except ValueError:
        return None

def check_script1(input_text):
    script_dict = {}
    for char in input_text:
        script = get_script(char)
        if script:
            if script not in script_dict:
                script_dict[script] = []
            script_dict[script].append(char)
    return script_dict

def script_identifier(input_script):
    script_dict = check_script(input_script)
    if not script_dict:
        return "No recognizable script found."
    else:
        result = "The identified letters grouped by script are:\n"
        for script, letters in script_dict.items():
            result += f"Script '{script}': {' '.join(letters)}\n"
        return result

# Function to check the font of a text
def check_font(text):
    # In this example, we assume that the font is Arial
    font = "Arial"  # Modify this to check the actual font
    return font

# Function to check the regular expression of the domain name
def check_domain_regex(domain):
    pattern = r"^[A-Za-z0-9-]+$"
    try:
        if not re.match(pattern, domain, timeout=1):
            return "Potential issue"
        return "Domain name matches the expected pattern"
    except re.TimeoutError:
        return "Pattern evaluation timed out. Potential ReDoS detected."
def check_domain_regex1(domain):
    pattern = r"^[A-Za-z0-9-]+$"
    match = re.search(pattern, domain)
    if not match:
        problematic_characters = [char for char in domain if not re.match(r'[A-Za-z0-9-]', char)]
        return f"Invalid character(s) detected: {', '.join(problematic_characters)}" if problematic_characters else "No issues found"
    return "Domain name matches the expected pattern"

# Function to check if the letters of the domain name are from ASCII or Unicode
def check_ascii_unicode(domain):
    ascii_chars = [char for char in domain if ord(char) <= 127]
    if len(ascii_chars) == len(domain):
        return "Domain name consists of ASCII characters"
    return "Domain name contains Unicode characters"

def analyze_url(url):
        #content = fetch_url_content(url)
        # Perform URL analysis
        analysis_result = "Safe"  # Placeholder result
        domain_name = tldextract.extract(url).domain
        script_result = check_script(domain_name)
        scripts = check_script1(domain_name)
        font_result = check_font(domain_name)
        ascii_unicode_result = check_ascii_unicode(domain_name)
        regex_result = check_domain_regex1(domain_name)
        phishtank_check_result = check_phishtank(url)

        if ("potential issue" in regex_result or "Domain name uses multiple scripts" in script_result):
            analysis_result = "Unsafe"
       # Return the results as a dictionary
        results = {
            "analysis_result": analysis_result,
            "domain_name": domain_name,
            "script_result": script_result,
            "scripts": scripts,
            "font_result": font_result,
            "ascii_unicode_result": ascii_unicode_result,
            "regex_result": regex_result,
            "phishtank_check_result": phishtank_check_result,
        }
        return results

    # If content is None, return an error message
# Define a route for the home page
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        results = analyze_url(url)
        return render_template("index.html", results=results)
    return render_template("index.html", results=None)
@app.route('/help')
def help():
    return render_template("help.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/tips')
def tips():
    return render_template("tips.html")
@app.route("/go_further")
def go_further():
    # Retrieve any necessary data for the "Go Further" page
    url = request.args.get("url")
    return render_template("go_further.html", url=url)

if __name__ == "__main__":
    app.run(host="localhost", port=5000, debug=True)
