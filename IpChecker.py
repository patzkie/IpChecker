import requests
import sys

ip = sys.argv[1]
if len(sys.argv) != 2:
    print("Usage: python IpChecker.py <IP>")
    sys.exit(1)
else:
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
	#api key from dump account HEHE
	headers = {"accept": "application/json", "x-apikey": "e78909e237c546c0672de15e2fd82b9de766985c8ea7db58c2f1a38ef37689ce"}
	response = requests.get(url, headers=headers)
	res = response.json()
	print('Harmless: ', res["data"]["attributes"]["total_votes"]["harmless"])
	print('Malicious: ',res["data"]["attributes"]["total_votes"]["malicious"])

