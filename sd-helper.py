import requests
import dns.resolver

domain = "domain.com"
apikey = "NULL"

def banner():
    # print("##     ##  #######  ##     ##    ##   ########\n###   ### ##     ## ##     ##  ####   ##    ##\n#### #### ##     ## ##     ##    ##       ##\n## ### ## ##     ## #########    ##      ##\n##     ## ##     ## ##     ##    ##     ##\n##     ## ##     ## ##     ##    ##     ##\n##     ##  #######  ##     ##  ######   ##\n")
    print("Author: M0H17")

banner()

def total():
    url="https://www.virustotal.com/vtapi/v2/domain/report?apikey="+ apikey + "&domain=" + domain
    try:
        resp = requests.get(url)
        resp = resp.json()
        subdomains = resp["subdomains"]
        file = open("vt_subdomains" , "w+")
        print("Extracting Subdomains from Virustotal")
        for subdomain in subdomains:
            file.write(subdomain + "\n")
    except Exception as e:
        print("Exception: " + str(e))

def dnss(sub):
    out = ""
    try:
        for test in dns.resolver.query(sub,"CNAME"):
            out = test.target
        return out
    except Exception as e:
        return e

def storage1():
    print("Checking VirusTotal Subdomains")
    total()
    file = open("vt_subdomains", "r")
    print("~"*160)
    for subdomain in file.readlines():
        subdomain=subdomain.rstrip('\n\r')
        try:
            r = requests.get('http://'+subdomain)
            protocol = r.url.split('://')[0]
            try:
                res = requests.get(str(protocol) + "://" + subdomain)
                try:
                    out = dnss(subdomain)
                    print("Host:\t" + subdomain + "\n" + "Status:\t" + str(res.status_code) + "\n" + "Server Version:\t" + res.headers.get("server")+ "\n" + "CNAME:\t" + str(out))
                    print("~" * 160)
                except Exception as exc:
                    if ("CNAME" in str(exc)):
                        print("Host:\t" + subdomain + "\n" + "Status:\t" + str(res.status_code) + "\n" + "Server Version:\t" + res.headers.get("server") + "\n" + "CNAME:\t" + str(exc))
                        print("~" * 160)
                        continue
            except Exception as e:
                print("exception here" + str(e))
                continue
        except Exception as e:
            continue
    print("Listed all Sub-Domains found on VirusTotal")
    print("\nYou can check results upto till done scanning process in the vt_subdomains.txt file")

def storage2():
    check = input("Do you want to check subdomains using wordlist (Y/N)")
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
                    print("Host:\t" + subd + "\n" + "Status:\t" + str(res.status_code) + "\n" + "Server Version:\t" + res.headers.get("server") + "\n" + "CNAME:\t" + str(out))
                    print("~" * 160)
                except Exception as exc:
                    if ("CNAME" in str(exc)):
                        print("Host:\t" + subd + "\n" + "Status:\t" + str(res.status_code) + "\n" + "Server Version:\t" + res.headers.get("server") + "\n" + "CNAME:\t" + str(exc))
                        print("~" * 160)
                        continue
            except:
                continue

if(apikey != "NULL"):
    storage1()
    storage2()
else:
    print("You might have not provided the virustotal API-KEY in the script.")
    storage2()

