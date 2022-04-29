
import requests
from sys import exit
import re

fileHashValue = input("Enter your MD5 or SHA256 File Hash: ")
apiKey = input("Enter your API Key: ")
hashMatch = re.search(r"([a-fA-F\d]{32})", fileHashValue)

if (len(fileHashValue) != 32 and len(fileHashValue) != 64):
    print("Invalid Hash, try again")
    exit(0)
elif(hashMatch == None):
    print("Invalid Hash, try again")
    exit(0)



#calling api
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

#status codes
if ("error" in p):
    if('"code": "WrongCredentialsError"' in p or '"code": "AuthenticationRequiredError"' in p or '"code": "UserNotActiveError"' in p):
        print("API FAILED... Status Code: 401")
    elif('"code": "BadRequestError"' in p or '"code": "InvalidArgumentError"' in p or '"code": "NotAvailableYet"' in p or
        '"code": "UnselectiveContentQueryError"' in p or '"code": "UnsupportedContentQueryError"' in p):
        print("API FAILED... Status Code: 400")
    elif('"code": "ForbiddenError"' in p):
        print("API FAILED... Status Code: 403")
    elif('"code": "NotFoundError"' in p):
        print("API FAILED... Status Code: 404")
    elif('"code": "AlreadyExistsError"' in p):
        print("API FAILED... Status Code: 409")
    elif('"code": "FailedDependencyError"' in p):
        print("API FAILED... Status Code: 424")
    elif('"code": "QuotaExceededError"' in p or '"code": "TooManyRequestsError"' in p):
        print("API FAILED... Status Code: 429")
    elif('"code": "TransientError"' in p):
        print("API FAILED... Status Code: 503")
    elif('"code": "DeadlineExceededError"' in p):
        print("API FAILED... Status Code: 504")
elif('"data":' in p):
    print("Status Code: 200")

#how many AV's detected the file
numOfMalicious = re.search(r'("malicious":) \d+[,]',p )
strMalicious = (re.search(r'\d+', numOfMalicious.group(0)))
intMalicicous = int(strMalicious.group(0))

if(intMalicicous > 5):
    print("{} AV engines detected the file".format(intMalicicous))
elif(intMalicicous < 5):
    print("The file may be malicious. {} AV engines deteccted the file".format(intMalicicous))
elif(intMalicicous == 0):
    print("The file is clean")


