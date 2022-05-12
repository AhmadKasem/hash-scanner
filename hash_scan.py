
import requests
from sys import exit
import re




def main():

    p = VirusTotal().scanHash(hashInput())
    #status codes
    """ if ("error" in p):
        if('"code": "WrongCredentialsError"' in p or '"code": "AuthenticationRequiredError"' in p or '"code": "UserNotActiveError"' in p):
            statusCode = 401
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "BadRequestError"' in p or '"code": "InvalidArgumentError"' in p or '"code": "NotAvailableYet"' in p or
            '"code": "UnselectiveContentQueryError"' in p or '"code": "UnsupportedContentQueryError"' in p):
            statusCode = 400
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "ForbiddenError"' in p):
            statusCode = 403
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "NotFoundError"' in p):
            statusCode = 404
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "AlreadyExistsError"' in p):
            statusCode = 409
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "FailedDependencyError"' in p):
            statusCode = 424
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "QuotaExceededError"' in p or '"code": "TooManyRequestsError"' in p):
            statusCode = 429
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "TransientError"' in p):
            statusCode = 503
            print("API FAILED... Status Code: {}".format(statusCode))
        elif('"code": "DeadlineExceededError"' in p):
            statusCode = 504
            print("API FAILED... Status Code: {}".format(statusCode))
    elif('"data":' in p):
        statusCode = 200
        print("Status Code: {}".format(statusCode))

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
        #print(p) """

#calling api
class VirusTotal:
    def __init__(self):
        self.url = "https://www.virustotal.com/api/v3/files/"
        

    def scanHash(self, token):
        url = self.url + token
        self.headers = {
            "Accept": "application/json",
            "x-apikey": apiKey()
            }
        self.response = requests.get(url, headers=self.headers)
        scanResult = self.response.text
        ####
        if ("error" in scanResult):
            if('"code": "WrongCredentialsError"' in scanResult or '"code": "AuthenticationRequiredError"' in scanResult or '"code": "UserNotActiveError"' in scanResult):
                statusCode = 401
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "BadRequestError"' in scanResult or '"code": "InvalidArgumentError"' in scanResult or '"code": "NotAvailableYet"' in scanResult or
                '"code": "UnselectiveContentQueryError"' in scanResult or '"code": "UnsupportedContentQueryError"' in scanResult):
                statusCode = 400
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "ForbiddenError"' in scanResult):
                statusCode = 403
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "NotFoundError"' in scanResult):
                statusCode = 404
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "AlreadyExistsError"' in scanResult):
                statusCode = 409
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "FailedDependencyError"' in scanResult):
                statusCode = 424
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "QuotaExceededError"' in scanResult or '"code": "TooManyRequestsError"' in scanResult):
                statusCode = 429
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "TransientError"' in scanResult):
                statusCode = 503
                #print("API FAILED... Status Code: {}".format(statusCode))
            elif('"code": "DeadlineExceededError"' in scanResult):
                statusCode = 504
                #print("API FAILED... Status Code: {}".format(statusCode))
        elif('"data":' in scanResult):
            statusCode = 200
            print("Status Code: {}".format(statusCode))

        #how many AV's detected the file
        numOfMalicious = re.search(r'("malicious":) \d+[,]',scanResult )
        strMalicious = (re.search(r'\d+', numOfMalicious.group(0)))
        intMalicicous = int(strMalicious.group(0))

        if(intMalicicous > 5):
            print("{} AV engines detected the file".format(intMalicicous))
        elif(intMalicicous < 5 and intMalicicous != 0):
            print("The file may be malicious. {} AV engines deteccted the file".format(intMalicicous))
        elif(intMalicicous == 0):
            print("The file is clean")

        ####
        return(statusCode)

    

def hashInput():

    fileHashValue = input("Enter your MD5 or SHA256 File Hash: ")
    #apiKey = input("Enter your API Key: ")
    hashMatch = re.search(r"([a-fA-F\d]{32})", fileHashValue)

    if (len(fileHashValue) != 32 and len(fileHashValue) != 64):
        print("Invalid Hash, try again")
        exit(0)
    elif(hashMatch == None):
        print("Invalid Hash, try again")
        exit(0)
    else:
        return fileHashValue


def apiKey():
    apiKeyNumber = input("Enter your API Key: ")
    return apiKeyNumber



if __name__ == "__main__":
   main()
   #hashInput()
   VirusTotal()