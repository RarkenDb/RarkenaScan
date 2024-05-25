import re
import os
import urllib
import time
from headers import *
from cimiw import *
import getpass
from colorama import Fore, Style, init

init(autoreset=True)
os.system('clear')

# Predefined username and password
USERNAME = "Rarken"
PASSWORD = "@Dz23B829X231k8b#$@"

def save_login_status(status):
    with open("credentials.txt", "w") as file:
        file.write(status)

def check_login_status():
    if os.path.exists("credentials.txt"):
        with open("credentials.txt", "r") as file:
            status = file.read()
            if status == "logged_in":
                return True
    return False

def login():
    print(Fore.GREEN + '''
    #####################
       _     ___   ____ ___ _   _ _
     | |   / _ \ / ___|_ _| \ | | |
     | |  | | | | |  _ | ||  \| | |
     | |__| |_| | |_| || || |\  |_|
     |_____\___/ \____|___|_| \_(_)
    #####################
    ''')
    username = raw_input("Username: ")
    password = getpass.getpass("Password: ")
    
    if username == USERNAME and password == PASSWORD:
        print(Fore.GREEN + "LOGIN BERHASIL!!!!")
        save_login_status("logged_in")
        time.sleep(1)
        print(Fore.GREEN + "KAMU AKAN LOGIN DALAM 5 DETIK")
        time.sleep(5)
        print(Fore.GREEN + "SELAMAT MENGGUNAKAN")
    else:
        print(Fore.RED + "USERNAME ATAU PASSWORD SALAH!")
        time.sleep(1)
        print(Fore.RED + " IF YOU WANT BUY CHAT: wa.me/6282279233026")
        time.sleep(1)
        print(Fore.RED + "LUPA PASSWORD ATAU USER CHAT:wa.me/6282279233026")
        time.sleep(1)
        print(Fore.RED + "KAMU AKAN KELUAR DALAM 5 DETIK!!!")
        time.sleep(5)
        print(Fore.RED + "GOOD BYE:)")
        exit()

def urls_or_list():
    if not check_login_status():
        login()
    
    os.system('clear')
    print(Fore.GREEN + '''
    ##########################
     [+]_____Fiture RarkenScan______[+]
     [+]Web knight WAF Detecting
     [+]RCE Scanner
     [+]XSS Scanner
     [+]Error based SQL Injection
     [+] And More....
    ###########################
    ''')
    url_or_list = raw_input(" [!] Scan URL or List of URLs? [1/2]: ")
    if url_or_list == "1":
        url = raw_input(" [!] Enter the URL: ")
        if "?" in url:
            rce_func(url)
            xss_func(url)
            error_based_sqli_func(url)
            lfi_func(url)
            directory_traversal_func(url)
            command_injection_func(url)
            csrf_func(url)
            xssi_func(url)
            ssti_func(url)
            insecure_cookies_func(url)
            sqli_blind_func(url)
            xxes_func(url)
            nosql_injection_func(url)
            xxe_func(url)
            path_traversal_func(url)
            clickjacking_func(url)
        else:
            print(Fore.RED +"\n [Warning] " + Style.RESET_ALL + Style.BRIGHT + url + Style.RESET_ALL + Fore.RED +" is not a valid URL")
            print(Fore.RED +" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n")
            exit()
    if url_or_list == "2":
        os.system('clear')
        print(Fore.GREEN + '''
        ##########################
        [+]_____Fiture RarkenScan______[+]
        [+]Web knight WAF Detecting
        [+]RCE Scanner
        [+]XSS Scanner
        [+]Error based SQL Injection
        [+] And More....
        ###########################
       ''')
        urls_list = raw_input(Fore.GREEN+" [!] Enter the list file name .e.g [list.txt]: ")
        open_list = open(urls_list).readlines()
        for line in open_list:
            if "?" in line:
                links = line.strip()
                url = links
                print(Fore.GREEN+" \n [!] Now Scanning " + url)
                rce_func(url)
                xss_func(url)
                error_based_sqli_func(url)
                lfi_func(url)
                directory_traversal_func(url)
                command_injection_func(url)
                csrf_func(url)
                xssi_func(url)
                ssti_func(url)
                insecure_cookies_func(url)
                sqli_blind_func(url)
                xxes_func(url)
                nosql_injection_func(url)
                xxe_func(url)
                path_traversal_func(url)
                clickjacking_func(url)
            else:
                links = line.strip()
                url = links
                print(Fore.RED +"\n [Warning] " + Style.RESET_ALL + Style.BRIGHT + url + Style.RESET_ALL + Fore.RED +" is not a valid URL")
                print(Fore.RED +" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n")
        exit()

print(Fore.GREEN + '''
    ##############################################################
    #| "RarkenScan" Web Applications Security Scanner              #
    #|  Author : Rarken
    #|  Github : https://github.com/RarkenDb
    #|  TikTok : tiktok.com/@rarkenxyz
    #|  SELAMAT MENGGUNAKAN
    ##############################################################
    ''')

urls_or_list()
