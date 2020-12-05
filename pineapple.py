import requests, json
from requests.auth import HTTPBasicAuth
import time, datetime
import config

#API token from token module
API_TOKEN = config.API_TOKEN
wigle_username = config.wigle_username
wigle_password = config.wigle_password

def clean_ssid_list(ssid_list):

    results = json.dumps(ssid_list["ssidPool"]).split("\\n")
    results[0] = results[0][1:] # removes the first ' from the first item
    results.pop() # remove the last element since its useless

    # add other ssids that don't need to be queried
    known_ssids = ["xfinitywifi", "This LAN is our LAN", "thepandashack", "XFINITY", "ZOOM", "OTA", "MyHouse", "AHMOTA", "RICS", "Music Garden", "finn"]

    for i in known_ssids:
        results.remove(i)

    return results

# get input 
print("1. results from a scan")
print("2. ssid pool information")
action_type = input("> ")
action_type = int(action_type)
location = input("Location?: ")
current_time = str(int(time.time()))


if action_type == 1:
    scan_id = input("Enter the scan id: ")
    print("Copy and paste one of the following options to choose: ")
    results_type = input("out_of_range_clients, ap_list, unassociated_clients: ")

    payload = {
        "module":"Recon",
        "action":"loadResults",
        "scanID": scan_id,
        "apiToken": API_TOKEN
        }
    
    resp = requests.post("http://172.16.42.1:1471/api/", data=json.dumps(payload))
    results = json.loads(resp.text[6:])

    if results_type == "unassociated_clients" or results_type == "out_of_range_clients":
        

        output_file_final_list = []

        for i in results["results"][results_type]:
            
            if results_type == "unassociated_clients":
                mac_type = i["mac"]
                output_file = open("./{}_{}_unassociated_scan_results.json".format(location, current_time), "a")
            elif results_type == "out_of_range_clients":
                mac_type = i
                output_file = open("./{}_{}_out_of_range_scan_results.json".format(location, current_time), "a")

            r = requests.get("https://www.macvendorlookup.com/oui.php?mac=" + mac_type)
            if r.status_code == 200:
                r = json.loads(r.text)
                i["company"] = r[0]["company"]
                i["country"] = r[0]["country"]
                i["addressL1"] = r[0]["addressL1"]
                i["addressL2"] = r[0]["addressL2"]
                i["addressL3"] = r[0]["addressL3"]

                output_file_final_list.append(i)

        output_file.write(json.dumps(output_file_final_list))
        output_file.close()

    elif results_type == "ap_list":
        results = results["results"]["ap_list"]
        output_file = open("./{}_{}_ap_list_scan_results.json".format(location, current_time), "a")

        for i in results:
            # do a lookup of the ssid mac and add it to our dict
            r = requests.get("https://www.macvendorlookup.com/oui.php?mac=" + i["bssid"])
            if r.status_code == 200:
                r = json.loads(r.text)
                i["bssid_vendor"] = r[0]["company"]

            if i["clients"]:
                for j in i["clients"]:
                    r = requests.get("https://www.macvendorlookup.com/oui.php?mac=" + j["mac"])
                    if r.status_code == 200:
                        r = json.loads(r.text)
                        j["client_vendor"] = r[0]["company"]
                        
        #print(results)
        output_file.write(json.dumps(results))
        output_file.close()

elif action_type == 2:
    
    # get the date 30 days ago for the queries for latest ssid data
    now = datetime.datetime.now()
    last_month = now - datetime.timedelta(days=30)
    
    ap_pool = {"module":"PineAP","action":"getPool", "apiToken": API_TOKEN}
    resp = requests.post("http://172.16.42.1:1471/api/", data=json.dumps(ap_pool))
    results = json.loads(resp.text[6:])
    
    results = clean_ssid_list(results)

    auth = HTTPBasicAuth(wigle_username, wigle_password)
    final_ssid_results = []
    for i in results:
        r = requests.get("https://api.wigle.net/api/v2/network/search?lastupdt={}&freenet=false&paynet=false&ssid={}".format(last_month.strftime("%Y%m%d"),i), auth=auth).json()
        final_ssid_results.append(r)
        
    # write the results to a file
    f = open("./ssid_results_{}.json".format(current_time), "a")
    f.write(json.dumps(final_ssid_results))
    f.close()
