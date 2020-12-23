import requests, json
from requests.auth import HTTPBasicAuth
import time, datetime
import config

#API token from token module
API_TOKEN = config.API_TOKEN
wigle_username = config.wigle_username
wigle_password = config.wigle_password

# this outputs one of four files
# 1. {}_{}_unassociated_scan_results.json - list of all the clients not on an ap. includes mac vendor info
# 2. {}_{}_out_of_range_scan_results.json - same as the above except for clients that aren't seen anymore
# 3. {}_{}_ap_list_scan_results.json - scan results. takes an id of the scan. also has mac vendor info
# 4. ssid_results_{}.json - all ap probes. includes wigle data


def lookup_ssid_information(ssid_list):
        final_ssid_results = []
        auth = HTTPBasicAuth(wigle_username, wigle_password)

        for i in ssid_list:
            r = requests.get("https://api.wigle.net/api/v2/network/search?lastupdt={}&freenet=false&paynet=false&ssid={}".format(last_month.strftime("%Y%m%d"),i.rstrip()), auth=auth).json()
            print(r)
            if("results" in r):
                final_ssid_results.append(r["results"])

                # write the results to a file                                                         
                f = open("./results/ssid_results_{}.json".format(current_time), "a")
                f.write(json.dumps(final_ssid_results))
                f.close()

# this cleans the ssids if getting the data from the pineapple api
def clean_ssid_list_api(ssid_list):

    results = json.dumps(ssid_list["ssidPool"]).split("\\n")
    results[0] = results[0][1:] # removes the first ' from the first item
    results.pop() # remove the last element since its useless

    # add other ssids that don't need to be queried
    known_ssid_file = open("./known_ssids.txt", "r")
    known_ssids = ssid_file.readlines()
    known_ssids = []

    for i in known_ssids:
        for j in results:
            if i == j:
                results.remove(i.rstrip())

    return results

# this cleans the ssids if the data comes from a file
def clean_ssid_list_file(ssid_list):

    # add other ssids that don't need to be queried
    known_ssid_file = open("./known_ssids.txt", "r")
    known_ssids = ssid_file.readlines()
    known_ssids = []

    for i in known_ssids:
        for j in ssid_list:
            if i == j:
                ssid_list.remove(i.rstrip())
    
    return ssid_list

if __name__ == "__main__":
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

        if results_type == "unassociated_clients":
            
            output_file_final_list = []

            for i in results["results"][results_type]:

                if results_type == "unassociated_clients":
                    mac_type = i["mac"]
                    output_file = open("./results/{}_{}_unassociated_scan_results.json".format(location, current_time), "a")

                r = requests.get("https://www.macvendorlookup.com/oui.php?mac=" + mac_type)
                if r.status_code == 200 and r.text != "":
                    r = json.loads(r.text)

                    i["company"] = r[0]["company"]
                    i["country"] = r[0]["country"]
                    i["addressL1"] = r[0]["addressL1"]
                    i["addressL2"] = r[0]["addressL2"]
                    i["addressL3"] = r[0]["addressL3"]

                    output_file_final_list.append(i)

            output_file.write(json.dumps(output_file_final_list))
            output_file.close()

        elif results_type == "out_of_range_clients":
            print("out of range clients")
            output_file = open("./results/{}_{}_out_of_range_scan_results.json".format(location, current_time), "a")
            
            output_file_final_list = []
            
            for i in results["results"][results_type]:
                r = requests.get("https://www.macvendorlookup.com/oui.php?mac=" + i)
                if r.status_code == 200:
                    r = json.loads(r.text)
                    out_of_range_info = {"ssid": i, 
                                        "company": r[0]["company"], 
                                        "country": r[0]["country"],
                                        "addressL1": r[0]["addressL1"],
                                        "addressL2": r[0]["addressL2"],
                                        "addressL3": r[0]["addressL3"]}
                    output_file_final_list.append(out_of_range_info)

            output_file.write(json.dumps(output_file_final_list))
            output_file.close()        

        elif results_type == "ap_list":
            results = results["results"]["ap_list"]
            output_file = open("./results/{}_{}_ap_list_scan_results.json".format(location, current_time), "a")

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

        file_location = input("Get results from API or FILE: ")
        
        if file_location == "API":
            ap_pool = {"module":"PineAP","action":"getPool", "apiToken": API_TOKEN}
            resp = requests.post("http://172.16.42.1:1471/api/", data=json.dumps(ap_pool))
            results = json.loads(resp.text[6:])

            results = clean_ssid_list_api(results)

            auth = HTTPBasicAuth(wigle_username, wigle_password)
            final_ssid_results = []

            for i in results:
                r = requests.get("https://api.wigle.net/api/v2/network/search?lastupdt={}&freenet=false&paynet=false&ssid={}".format(last_month.strftime("%Y%m%d"),i), auth=auth).json()
                print(r)
                final_ssid_results.append(r["results"])
            
                # write the results to a file
                f = open("./results/ssid_results_{}.json".format(current_time), "a")
                f.write(json.dumps(final_ssid_results))
                f.close()

        elif file_location == "FILE":
            file_location = input("path to file: ")
            
            # eh, theres some kind of weird chars in the list
            ssid_file = open(file_location, "r", errors="ignore")
            ssid_list = ssid_file.read().splitlines()
            results = clean_ssid_list_file(ssid_list)

            lookup_ssid_information(results)