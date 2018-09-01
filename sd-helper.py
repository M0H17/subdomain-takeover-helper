import requests
import dns.resolver

domain = "domain-here"
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

def cnames(sub):
    cname = ""
    try:
        for test in dns.resolver.query(sub,"CNAME"):
            cname = test.target
        return str(cname)
    except Exception as e:
        return str(e)

def request_send(subdomain):
    try:
        r = requests.get('http://' + subdomain)
        protocol = r.url.split('://')[0]
        try:
            res = requests.get(str(protocol) + "://" + subdomain)
            try:
                cname = cnames(subdomain)
            except Exception as e1:
                cname = str(e1)
                pass
            ip = ipresolver(subdomain)
            printer(res, cname, ip)
        except Exception as e:
            print("Exception Occured While Sending Request 1: " + str(e))
    except Exception as e:
        if("Max retries exceeded with url" in str(e)):
            pass
        else:
            print("Exception Occured While Sending Request 2: " + str(e))

def storage1():
    print("Checking VirusTotal Subdomains")
    total()
    file = open("vt_subdomains", "r")
    for subdomain in file.readlines():
        subdomain=subdomain.rstrip('\n\r')
        request_send(subdomain)
    print("\nListed all Sub-Domains found on VirusTotal")
    print("You can check results upto till done scanning process in the vt_subdomains.txt file")

def ipresolver(subdomain):
    try:
        ip = dns.resolver.query(subdomain)
        for data in ip:
            return data
    except Exception as e:
        return str(e)

def printer(res,cname,ip):
    print("~"*30)
    print("IP: " + str(ip) + "\t\tHost:\t" + str(res.url) + "\n" + "Status:\t" + str(
        res.status_code) + "\t\t\t\t" + "Server Version:\t" + res.headers.get("server") + "\n" + "CNAME:\t" + str(
        cname) + "\n")

def storage2():
    check = input("\nDo you want to check subdomains using wordlist (Y/N)")
    check = str(check).lower()
    if(check == "y"):
        targets = open("wordlist.txt","r")
        content = targets.readlines()
        content = [x.strip() for x in content]
        for items in content:
            subomain = items + "." + domain
            request_send(subomain)

if(apikey != "NULL"):
    storage1()
    storage2()
else:
    print("You might have not provided the virustotal API-KEY in the script.")
    storage2()
