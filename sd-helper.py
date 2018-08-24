import requests
import dns.resolver

domain = "domain.com"
apikey = "NULL" 

def total():
    url="https://www.virustotal.com/vtapi/v2/domain/report?apikey="+ apikey + "&domain=" + domain
    resp = requests.get(url)
    resp = resp.json()
    subdomains = resp["subdomains"]
    file = open("vt_subdomains" , "w+")
    for subdomain in subdomains:
        file.write(subdomain + "\n")

def dnss(sub):
    out = ""
    for test in dns.resolver.query(sub,"CNAME"):
        out = test.target
    return out

def storage1():
    total()
    file = open("vt_subdomains", "r")
    for subdomain in file.readlines():
        subdomain=subdomain.rstrip('\n\r')
        r = requests.get('http://'+subdomain)
        protocol = r.url.split('://')[0]
        try:
            res = requests.get(str(protocol) + "://" + subdomain)
            try:
                out = dnss(subdomain)
                print(
                    str(res.status_code) + "\t\t" + subdomain + "\t\t" + str(res.headers.get("server")) + "\t\t" + str(out))
            except Exception as exc:
                if ("CNAME" in str(exc)):
                    print(str(res.status_code) + "\t\t" + subdomain + "\t\t" + str(res.headers.get("server")) + "\t\t" + str(exc))
                    continue
        except Exception as e:
            print("exception here" + str(e))
            continue
    print("\nYou can check results upto till done scanning process in the vt_subdomains.txt file")

def storage2():
    check = input("Do you want to check subdomains using wordlist (Y/N)")
    print("Status" + "\t\t" + "Host" + "\t\t\t\t\t\t\t" + "Server Version" + "\t\t\t\t" + "CNAME")
    check = str(check).lower()
    if(check == "y"):
        targets = open("wordlist.txt","r")
        content = targets.readlines()
        content = [x.strip() for x in content]
        for items in content:
            sub = items + "." + domain
            subd = "http://" + sub
            try:
                res = requests.get(subd)
                try:
                    out = dnss(sub)
                    print(str(res.status_code) + "\t\t\t" + subd + "\t\t" + str(res.headers.get("server")) + "\t\t" + str(out))
                except Exception as exc:
                    if ("CNAME" in str(exc)):
                        print(str(res.status_code) + "\t\t\t" + subd + "\t\t" + str(res.headers.get("server")) + "\t\t" + str(exc))
                        continue
            except:
                continue

if(apikey != "NULL"):
    storage1()
    storage2()
else:
    print("You might have not provided the virustotal API-KEY in the script.")
    storage2()

