import json
import requests
import copy
import datetime;
import random
import time

from confluent_kafka import Producer
import socket
from datetime import datetime
import json
import uuid
import random

config = open("config.json").read()
config = json.loads(config)
appserverurl = config['iotacappserver_kafka']
metadata = config['metadata']
honeypotlog = config['logfilepath']


conf = {"bootstrap.servers": appserverurl, "client.id": socket.gethostname()}
producer = Producer(conf)
topic = "IOTAC.HP.RMS"

# get public ip for report
try:
	publicip = str(requests.get('https://checkip.amazonaws.com').text.strip())
except Exception as e:
	print ("can not resolve public IP, use 127.0.0.1 for report")
	publicip = "127.0.0.1"

HONEYPOT_UUID = "HONEYPOT-"+str(random.randint(10000,99999))

print("[PushAPI.py] Testing kafka connection via "+appserverurl)

# try to contact kafka, breaks if reachable
while 1:
	try:
		ct = datetime.now() # .isoformat()	
		stamp = str(ct.strftime("%m/%d/%Y, %H:%M:%S") )

		testmsg = {
			"dataSourceID": HONEYPOT_UUID,		# 'IoTAC_HP-SMARTHOME11'
			"systemID": HONEYPOT_UUID, 					# "CERTH_Smart_Home-1_IoT-System"
			"reportType": "IoTAC-Threat-Report",
			"_timestamp": stamp,
			"location": metadata["location"],
			"value": {
					"type": "Honeypot",
					"monitoredAssetID": HONEYPOT_UUID,
					"monitoredAssetIP": [publicip],
					"measurement": [{"name": "Status", "value": "Honeypot initiated."}],
					"requestSource": publicip,
					"_timestamp": stamp
			}
		}

		# test if kafka is avilible
		json_send = json.dumps(testmsg).encode()
		producer.produce("IOTAC.HP.RMS", key=str(uuid.uuid4()), value=json_send)
		producer.flush()
		break;
	
	except Exception as e:
		print (e)
		print ("[PushAPI.py] kafka not reachable via "+appserverurl)
		print ("[PushAPI.py] try again in 10 min ... ")
		time.sleep(600) 

# exit()

print ("[PushAPI.py] Kafka reachable via "+appserverurl)
print ("[PushAPI.py] Share honeypot theat infos to "+appserverurl)
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
	"dataSourceID": HONEYPOT_UUID,		# 'IoTAC_HP-SMARTHOME11'
	"systemID": HONEYPOT_UUID, 			# "CERTH_Smart_Home-1_IoT-System"
	"reportType": "IoTAC-Threat-Report",
	"_timestamp": stamp,
	"location": metadata["location"],
	"value": {
			"type": "Honeypot",
			"monitoredAssetID": HONEYPOT_UUID,
			"monitoredAssetIP": publicip,
			"measurement": [
				# {"name": "Login", "value": "login attempt [root/mysmartpassword] succeeded"},
				# {"name": "sessionID", "value": "e2cf44beaa85"}
			],
			"requestSource": publicip,
			"_timestamp": stamp
	}
}


sessionIPdict = {}

if __name__ == '__main__':
	# logfile = open("examplelog/honeypot2.json","r")
	logfile = open(honeypotlog,"r")
	loglines = follow(logfile)

	for line in loglines:
		lineobj = json.loads(line)

		# prepare log entry message
		logmsg = copy.copy(header)
		# update message timestamp
		ct = datetime.now() # .isoformat()	
		stamp = str(ct.strftime("%m/%d/%Y, %H:%M:%S") )
		logmsg["_timestamp"] = stamp

		sendevent = False

		# if attacker IP is not in the log entry, look it up via session ID
		if("dst_ip" not in lineobj):
			lineobj["dst_ip"] = sessionIPdict[lineobj["session"]]
		else:
			try:
				sessionIPdict[lineobj["session"]] = lineobj["dst_ip"]
			except Exception as e:
				lineobj["dst_ip"] = "0.0.0.0"

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

			# send logmsg
			try:
				print ("send log line to kafka")
				# print (logmsg)
				# test if kafka is avilible
				json_send = json.dumps(logmsg).encode()
				producer.produce("IOTAC.HP.RMS", key=str(uuid.uuid4()), value=json_send)
				producer.flush()
				# break;
				# r = requests.post(appserverurl, line, timeout=30)
				# print("[PushAPI.py]: HTTP Response "+str(r.status_code))
		

			except Exception as e:
				print ("[PushAPI.py]: Kafka communication error ...")
				print (e)






