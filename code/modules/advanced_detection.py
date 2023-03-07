import psutil
import hashlib
import time
import json
import requests

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_remote_log( ip ):
	remote_api = "https://"+ip+"/getall"
	print ("[advanced_detection] fetch log data from ",remote_api)
	try:
		reqheader = { "apikey" : "iotacAPIkey1-s56JkyKbk4WrSBaXt9M99PC9XpGtUKZu9T" }
		r = requests.get(remote_api, verify=False, headers=reqheader)
		remote_data = r.text.strip().split("\n")
	except Exception as e:
		print ("[advanced_detection] can not access remote log "+remote_api)
		return {}

	if(len(remote_data) <= 2):
		return "{}"

	# remote_data = open("cowrie2.json", "r").readlines()  # local testing
	remote_data_json = []

	for x in remote_data:
		print (len(x), x)
		remote_data_json.append( json.loads( x ) )
	return (remote_data_json)


def getip(vdict):
	for e in vdict:
		if('dst_ip' in e):
			return (e['dst_ip'])
	return "NOIP"


def create_shared_threat(local, remote, localIP, remoteIP):
	threat_info = local.copy()
	# print ("NEW SHARED THREAT")
	threat_info.pop('sensor', None)
	threat_info.pop('session', None)
	if('iotac.honeypot.client.kex' in local['eventid']):
		threat_info.pop('hasshAlgorithms', None)
		threat_info.pop('kexAlgs', None)
		threat_info.pop('keyAlgs', None)
		threat_info.pop('encCS', None)
		threat_info.pop('macCS', None)
		threat_info.pop('compCS', None)
		threat_info.pop('langCS', None)
	
	threat_info['shared_by'] = remoteIP
	# print (threat_info)
	# print ("")
	return threat_info

import socket   
hostname=socket.gethostname()   
localIP=socket.gethostbyname(hostname)   
print (localIP)

# look for common threats between this and remote honeypots
def advanced_detection(threat_history, offset):
	print ("[advanced_detection] check regularly for shared threats with other honeypots")

	logfd = open(logfilepath, "r")
	local_log = logfd.readlines()
	logfd.close()

	local_log = local_log[offset:]

	for i in range(0, len(local_log)):
		local_log[i] = json.loads( local_log[i].replace("cowrie", "iotac.honeypot") )


	for ip in list_of_nodes:				# list of honeypots
		# remoteIP = ip.split(":")[0]
		# if(localIP == remoteIP):			# skip localhost
			# continue;

		remote_log = get_remote_log(ip)
		if(len(remote_log) == 0):
			break;

		local_ip = getip(local_log)
		remote_ip = getip(remote_log)

		threats = []

		for local in local_log:
			if('shared_by' in local):
				continue # ignore shared threats that are already published
			
			# ignore some arbitary cases
			if('message' not in local):
				continue
			if(len(local['message']) == 0):
				continue
			if(local['eventid'] == 'iotac.honeypot.session.closed'):
				continue

			# for each entry, evaluate against remote entry
			for remote in remote_log:
				# print (" ", remote['eventid'])
				if('shared_by' in remote):
					continue # ignore shared threats that are already published

				if( local['eventid'] ==  remote['eventid']):
					# print (" ", remote['eventid'], " -> same event")

					if(local['src_ip'] == remote['src_ip']):
						# print (local['message'])
						# print (remote['message'])

						# in most cases the same message -> same attack
						if(local['message'] == remote['message']):
							threat_info = create_shared_threat( local, remote, local_ip, remote_ip )
							threats.append( threat_info )
							break

						# add some corner cases
						# e.g. New connection: 172.17.0.3:38050 (172.17.0.2:2222) [session: a528d006c288] -> looks different
						if('iotac.honeypot.session.connect' in local['eventid']): # has to be the same
							local['message'] = ' '.join( local['message'].split(":")[0:2] )		# remove some random port info
							remote['message'] = ' '.join( remote['message'].split(":")[0:2] )
							
							threat_info = create_shared_threat( local, remote, local_ip, remote_ip )
							threats.append( threat_info )
							break

					# print ("")

		# report all shared threats into the log

		logfile = open( logfilepath, 'a')

		for t in threats:
			if( t in threat_history ):
				# print ("FOUND IN HISTORY")
				threat_history.append(t)
				continue
			print ("[advanced_detection] shared threat -> log ("+t['message']+")")

			try:
				json_txt = str(json.dumps(t))
				logfile.write( json_txt+"\n" ) 
			except Exception as e:
				print ("can not access log to write shared threats")
				raise e
		
		logfile.close()


	return (len(local_log))



if __name__ == '__main__':

	config = open("config.json").read()
	config = json.loads(config)
	list_of_nodes = config['nodes']

	logfilepath = config['logfilepath']

	threat_history = []

	print ("[advanced_detection] initiated, share threat across: "+str(list_of_nodes))

	offset = 0
	time.sleep(10)

	while True:
		offset += advanced_detection( threat_history, offset )
		time.sleep(60*10) # check every 10 minutes for remote updates






		


