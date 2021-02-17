#python imports
import requests
import concurrent.futures
import threading
import random
import time
import sys
from colorama import init,Fore
init()

#greywolf imports
from lib import userAgent


class Brute():

    def __init__(self,address,usernames,passwordPath,proxyPath = None):
        self.address = address
        self.passwordPath = fr"{passwordPath}"
        self.proxyPath = proxyPath
        self.usernames = usernames

        self.userAgents = userAgent.userAgents
        self.proxies = []
        self.passwords = []


        self.threadLocal = threading.local()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers = 128)


    def readPasswords(self):
        """
        Open given file, append lines to the list and return the list.
        """
        try:
            passwordFile = open(self.passwordPath,"r")
            for line in passwordFile.readlines():
                password = line.strip()
                if len(password) > 1:
                    self.passwords.append(password)

        except:
            print(Fore.RED + f"[ERROR] {self.passwordPath} is missing.")
            time.sleep(3)
            sys.exit()


    def readProxies(self):
        """
        If user defines a proxy file, check proxy format, append proxies to a list and return the list
        """
        if not self.proxyPath:
            return None

        try:
            self.proxyPath = fr"{self.proxyPath}"
            proxyFile = open(fr"{self.proxyPath}","r")
            for line in proxyFile.readlines():
                proxy = line.strip()
                if len(proxy) > 1:
                    if "http" not in proxy and proxy.count(".") == 3 and proxy.count(":") == 1:
                        self.proxies.append({"http":proxy,"https":proxy})

                    else:
                        print(Fore.RED + "[ERROR] Invalid proxy, proxy format should be like 1.1.1.1:80")

        except:
            print(Fore.RED + f"[ERROR] {self.proxyPath} is missinaaag..")


    def createHeaders(self):
        """
        Returns simple http/s headers.
        """
        return {
            "User-Agent":random.choice(self.userAgents),
            "Connection":"keep-alive",
            "Accept":"text-html",
            "Refereer":"https://www.google.com",
            "Accept-Language":"en-US,en;q=0.9,la;q=0.8"
        }


    def getSession(self):
        if not hasattr(self.threadLocal, "session"):
            self.threadLocal.session = requests.Session()
        return self.threadLocal.session









