import json
import requests
import copy
import datetime;
import random
import time


config = open("config.json").read()
config = json.loads(config)
appserverurl = config['iotacappserver_kafka'][0]
metadata = config['metadata']


print("[PushAPI.py] Testing kafka connections via "+appserverurl)
# try to contact kafka, breaks if reachable
while True:
	try:
		ct = datetime.datetime.now().isoformat()
		testmsg = {
			"dataSourceID": metadata["dataSourceID"],		# 'IoTAC_HP-SMARTHOME11'
			"systemID": metadata["systemID"], 			# "CERTH_Smart_Home-1_IoT-System"
			"reportType": "IoTAC-Threat-Report",
			"_timestamp": str(ct),
			"location": metadata["location"],
			"value": {
				"type": "AttackDetection",
				"monitoredAssetID": metadata["monitoredAssetID"],
				"monitoredAssetIP": ["127.0.0.1"],
				"measurement": [{"name": "Status", "value": "Honeypot initiated."}],
			"requestSource": "127.0.0.1",
			"_timestamp": "2020-01-01T00:00:00.000Z"
		  }
		}

		# test if kafka is avilible
		r = requests.post(appserverurl, str(testmsg), timeout=30)
		print("[PushAPI.py] "+r.status_code)
		break;
	except Exception as e:
		# print (e)
		print ("[PushAPI.py] kafka not reachable via "+appserverurl)
		print ("[PushAPI.py] try again in 10 min ... ")

	time.sleep(600) 

print ("[PushAPI.py] Kafka reachable via "+appserverurl)
print ("[PushAPI.py] Send honeypot theat infos to "+appserverurl)
print (" ")

def follow(thefile):
	 # thefile.seek(0,2)  # skip old log entries
	 while True:
			line = thefile.readline()
			if not line:
				time.sleep(0.1)
				continue
			yield line

# print (metadata)


header = {
  "dataSourceID": metadata["dataSourceID"],		# 'IoTAC_HP-SMARTHOME11'
  "systemID": metadata["systemID"], 			# "CERTH_Smart_Home-1_IoT-System"
  "reportType": "IoTAC-Threat-Report",
  "_timestamp": "2020-01-01T00:00:00.000Z",
  "location": metadata["location"],
  "value": {
	"type": "AttackDetection",
	"monitoredAssetID": metadata["monitoredAssetID"],
	"monitoredAssetIP": ["127.0.0.1"],
	"measurement": [
		# {"name": "Login", "value": "login attempt [root/mysmartpassword] succeeded"},
		# {"name": "sessionID", "value": "e2cf44beaa85"}
	],
	"requestSource": "127.0.0.1",
	"_timestamp": "2020-01-01T00:00:00.000Z"
  }
}


# header["value"]["test"] = "123"
# print (header["value"])
# exit()

sessionIPdict = {}


if __name__ == '__main__':
	logfile = open("examplelog/honeypot2.json","r")
	loglines = follow(logfile)
	for line in loglines:
		lineobj = json.loads(line)

		# prepare log entry message
		logmsg = copy.copy(header)
		# update message timestamp
		ct = datetime.datetime.now().isoformat()
		logmsg["_timestamp"] = str(ct)

		sendevent = False

		# if attacker IP is not in the log entry, look it up via session ID
		if("dst_ip" not in lineobj):
			lineobj["dst_ip"] = sessionIPdict[lineobj["session"]]
		else:
			sessionIPdict[lineobj["session"]] = lineobj["dst_ip"]


		logmsg["value"]["monitoredAssetIP"] = lineobj["src_ip"] # honeypot IP
		logmsg["value"]["requestSource"] = lineobj["dst_ip"]	# attacker IP
		logmsg["value"]["_timestamp"] = lineobj["timestamp"] 	# timestamp of event

		if("iotac.honeypot.login." in lineobj["eventid"]):
			sendevent = True
			print ("[PushAPI.py] found login ... send:")

		if("iotac.honeypot.command." in lineobj["eventid"]):
			sendevent = True
			print ("[PushAPI.py] found cmd ... send:")

		if("iotac.honeypot.session.connect" in lineobj["eventid"]):
			sendevent = True
			print ("[PushAPI.py] found ssh, ftp, ... send:")
			logmsg["value"]["monitoredAssetIP"] = lineobj["src_ip"] # honeypot IP
			logmsg["value"]["requestSource"] = lineobj["dst_ip"]	# attacker IP
			logmsg["value"]["_timestamp"] = lineobj["timestamp"] 	# timestamp of event

		if(sendevent):
			# copy all other info over
			logmsg["value"]["measurement"] = []
			for item in lineobj.items():
				# remove duplicated data that is added already
				if(item[0] in ["src_ip", "dst_ip", "timestamp"]):
					continue
				# copy the rest from log entry to logmsg
				e = {"name": item[0], "value": item[1] }
				# print (e)
				logmsg["value"]["measurement"].append(e)

			print (logmsg)

			# finally send logmsg
			try:
				print ("send ...")
				# r = requests.post('http://httpbin.org/post', line)
				r = requests.post(appserverurl, line, timeout=30)
				print("[PushAPI.py]: HTTP Response "+str(r.status_code))
				# print (" ")
		
			except Exception as e:
				print ("[PushAPI.py]: Kafka communication error ...")
				print (e)






