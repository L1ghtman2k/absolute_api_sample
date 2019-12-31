from datetime import datetime
import hashlib
import hmac
import requests

apiMethod = "GET"
apiURL = "https://api.absolute.com"
apiService = "/v2/reporting/devices"
apiHost = "api.absolute.com"
apiQuery = ""    # apiQuery = "%24top=1"
apiPayload = ""  
apiToken =  "" #### FOLLOWING FIELD IS REQUIRED ####
apiSecret = "" #### FOLLOWING FIELD IS REQUIRED ####
xDate = datetime.today().strftime('%Y%m%d')
xDateTime = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

def hash(request):
    hash = hashlib.sha256(bytes(request, 'UTF-8'))
    return hash

def HmacSHA256(request, secret):
    content = bytes(request, 'UTF-8')
    signature = hmac.new(secret, msg=content, digestmod=hashlib.sha256)
    return signature

#### CREATE CANONICAL REQUEST ####
canHeader1 = f"host:{apiHost}"
canHeader2 = "content-type:application/json"
canHeader3 = f"x-abs-date:{xDateTime}"

hasher = hash(apiPayload)
apiPayloadHash = hasher.hexdigest()
CanonicalRequestString = f"{apiMethod}\n{apiService}\n{apiQuery}\n{canHeader1}\n{canHeader2}\n{canHeader3}\n{apiPayloadHash}"
hasher = hash(CanonicalRequestString)
CanonicalRequestHash = hasher.hexdigest()


#### CREATE STRING TO SIGN ####
strAlgorithim = "ABS1-HMAC-SHA-256"
strRequestDateTime = xDateTime
strCredentialScope = f"{xDate}/cadc/abs1"
StringToSign = f"{strAlgorithim}\n{strRequestDateTime}\n{strCredentialScope}\n{CanonicalRequestHash}"

#### CREATE SIGNING KEY ####
xSecret = f"ABS1{apiSecret}"
kSecret = bytes(xSecret, 'UTF-8')
kDate = HmacSHA256(xDate, kSecret)
kDate = bytes.fromhex(kDate.hexdigest())
kSigning = HmacSHA256("abs1_request", kDate)
kSigning = bytes.fromhex(kSigning.hexdigest())
kSignature = HmacSHA256(StringToSign, kSigning)
signature = kSignature.hexdigest()


#### CREATE API REQUEST ####
apiURLaction = f"{apiURL}{apiService}?{apiQuery}"
authString = f"ABS1-HMAC-SHA-256 Credential={apiToken}/{xDate}/cadc/abs1, SignedHeaders=host;content-type;x-abs-date, Signature={signature}"
headers = {}
headers["host"] = "api.absolute.com"
headers["content-type"] = "application/json"
headers["x-abs-date"] = xDateTime
headers["authorization"] = authString

#### PRINT OUTPUT ####
result = requests.get(url=apiURLaction, headers=headers)
print(result.text)