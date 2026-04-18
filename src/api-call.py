import hashlib, requests, sys

def check_hibp(password):
    hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = hash[:5], hash[5:] #splits the hash
    headers = {"User-Agent": "PasswordSecurityChecker/1.0"} #user agent header
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers=headers) #sends only the first 5 characters of the hash
    
    for line in response.text.splitlines():
        if line.startswith(suffix): #checks locally for the last 5 hash characters
            count = int(line.split(":")[1])
            return count  # found, return how many times
    
    return 0  # not found

print(check_hibp(sys.argv[1])) #sys.argv[1] represents the password from the C code