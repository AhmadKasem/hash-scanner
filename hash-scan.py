import requests
from sys import exit
import re

fileHashValue = input("Enter your MD5 or SHA256 File Hash: ")
apiKey = input("Enter your API Key: ")
hashMatch = re.search(r"([a-fA-F\d]{32})", fileHashValue)

if (len(fileHashValue) != 32 and len(fileHashValue) != 64 and hashMatch != None):
    print("Invalid Hash, try again")
    exit(0)
    




class VirusTotal:
    def __init__(self, token):
        self.url = "https://www.virustotal.com/api/v3/files/"
        

    def scanHash(self):
        url = self.url + fileHashValue
        self.headers = {
            "Accept": "application/json",
            "x-apikey": apiKey
            }
        self.response = requests.get(url, headers=self.headers)

        return(self.response.text)

p = VirusTotal(apiKey).scanHash()

print(p)