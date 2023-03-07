import json
import requests

config = open("config.json").read()
config = json.loads(config)
appserver = config['iotacappserver']

import time
def follow(thefile):
	 # thefile.seek(0,2)  # skip old log entries
	 while True:
			line = thefile.readline()
			if not line:
				time.sleep(0.1)
				continue
			yield line


header = {
		"dataSourceID": "IoTAC_HP-1",
		"systemID":"CERTH_Smart_Home-1_IoT-System",
		"reportType": "AttackType",
		"timestamp": "2022-08-01 13:03:37.861639",
		"location": {"virtualLocation": "CERTH_Smart_House-1"},
		"value": {
			"monitoredAssetID": ["SmartHomeHoneypot-1"],
			"monitoredAssetIP": ["10.10.107.222"],
			"attackType": "Login",
			"threatInfo": "login attempt [root/!root] succeeded",
			"sessionID":"e2cf44beaa85",
			"requestSource":"183.251.22.15",
			"timestamp": "2022-08-01 13:03:19.709098"}
		}

print (header)
exit()


if __name__ == '__main__':
	 logfile = open("examplelog/honeypot2.json","r")
	 loglines = follow(logfile)
	 for line in loglines:
			try:
				r = requests.post('http://httpbin.org/post', line)
				print(r.status_code)
				print (line)
			except Exception as e:
				raise e
			





