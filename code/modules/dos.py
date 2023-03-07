import time
import asyncio
from datetime import datetime
from quart import Quart, websocket, request, render_template
import signal
import os
import sys
import ctypes
import threading
from scapy.all import *
from queue import Queue
import random
import optparse
import json 


class DOSdetect():
	def __init__(self):
		self.INTERFACE = conf.iface
		self.MY_IP = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3]==self.INTERFACE][0]
		self.MY_MAC = get_if_hwaddr(self.INTERFACE)
		self.WEBSOCKET = None
		self.PACKETS_QUEUE = Queue()
		self.MAC_TABLE = {}
		self.RECENT_ACTIVITIES = []
		self.FILTERED_ACTIVITIES = {
			'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
			'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
			'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
			'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
		}
		self.flag = False

	def sniffer_threader(self):
		while self.flag:
			pkt = sniff(count=1)
			with threading.Lock():
				self.PACKETS_QUEUE.put(pkt[0])

	def analyze_threader(self):
		while self.flag:
			pkt = self.PACKETS_QUEUE.get()
			self.analyze_packet(pkt)
			self.PACKETS_QUEUE.task_done()

	def check_avg_time(self, activities):
		time = 0
		c = -1
		while c>-31:
			time += activities[c][0] - activities[c-1][0]
			c -= 1
		time /= len(activities)
		return ( time<2 and self.RECENT_ACTIVITIES[-1][0] - activities[-1][0] < 10)
	
	def set_flags(self):
		for category in self.FILTERED_ACTIVITIES:
			if len(self.FILTERED_ACTIVITIES[category]['activities']) > 20:
				# self.FILTERED_ACTIVITIES[category]['flag'] = check_avg_time( self.FILTERED_ACTIVITIES[category]['activities'] )
				activities = self.FILTERED_ACTIVITIES[category]['activities']
				time = 0
				c = -1
				while c >- len(activities):
					time += activities[c][0] - activities[c-1][0]
					c -= 1
				time /= len(activities)
				self.FILTERED_ACTIVITIES[category]['flag'] = ( time<2 and self.RECENT_ACTIVITIES[-1][0] - activities[-1][0] < 10)
			
				if self.FILTERED_ACTIVITIES[category]['flag']:
					self.FILTERED_ACTIVITIES[category]['attacker-mac'] = list(set( [i[4] for i in self.FILTERED_ACTIVITIES[category]['activities']] ))

	
	def analyze_packet(self, pkt):
		src_ip, dst_ip, src_port, dst_port, tcp_flags, icmp_type = None, None, None, None, None, None
		protocol = []

		if len(self.RECENT_ACTIVITIES) > 15:
			self.RECENT_ACTIVITIES = self.RECENT_ACTIVITIES[-15:]
		
		for category in self.FILTERED_ACTIVITIES:
			if len(self.FILTERED_ACTIVITIES[category]['activities']) > 30:
				self.FILTERED_ACTIVITIES[category]['activities'] = self.FILTERED_ACTIVITIES[category]['activities'][-30:]

		self.set_flags()

		src_mac = pkt[Ether].src if Ether in pkt else None
		dst_mac = pkt[Ether].dst if Ether in pkt else None
			
		if IP in pkt:
			src_ip = pkt[IP].src
			dst_ip = pkt[IP].dst
		elif IPv6 in pkt:
			src_ip = pkt[IPv6].src
			dst_ip = pkt[IPv6].dst
		
		if TCP in pkt:
			protocol.append("TCP")
			src_port = pkt[TCP].sport
			dst_port = pkt[TCP].dport
			tcp_flags = pkt[TCP].flags.flagrepr()
		if UDP in pkt:
			protocol.append("UDP")
			src_port = pkt[UDP].sport
			dst_port = pkt[UDP].dport
		if ICMP in pkt:
			protocol.append("ICMP")
			icmp_type = pkt[ICMP].type # 8 for echo-request and 0 for echo-reply
		
		if ARP in pkt and pkt[ARP].op in (1,2):
			protocol.append("ARP")
			if pkt[ARP].hwsrc in self.MAC_TABLE.keys() and self.MAC_TABLE[pkt[ARP].hwsrc] != pkt[ARP].psrc:
				self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc
			if pkt[ARP].hwsrc not in self.MAC_TABLE.keys():
				self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc
		
		load_len = len(pkt[Raw].load) if Raw in pkt else None

		attack_type = None
		
		if ICMP in pkt:
			if src_ip == self.MY_IP and src_mac != self.MY_MAC:
				self.FILTERED_ACTIVITIES['ICMP-SMURF']['activities'].append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type])
				attack_type = 'ICMP-SMURF PACKET'

			if load_len and load_len>1024:
				self.FILTERED_ACTIVITIES['ICMP-POD']['activities'].append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type])
				attack_type = 'ICMP-PoD PACKET'

		if dst_ip == self.MY_IP:
			if TCP in pkt:
				if tcp_flags == "S":
					self.FILTERED_ACTIVITIES['TCP-SYN']['activities'].append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type])
					attack_type = 'TCP-SYN PACKET'

				elif tcp_flags == "SA":
					self.FILTERED_ACTIVITIES['TCP-SYNACK']['activities'].append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type])
					attack_type = 'TCP-SYNACK PACKET'

		self.RECENT_ACTIVITIES.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type])
		
	
	def start(self):
		if not self.flag:
			self.flag = True
			sniff_thread = threading.Thread(target=self.sniffer_threader)
			sniff_thread.daemon = True
			sniff_thread.start()
			analyze_thread = threading.Thread(target=self.analyze_threader)
			analyze_thread.daemon = True
			analyze_thread.start()
		return self.flag
	
	def stop(self):
		self.flag = False
		self.PACKETS_QUEUE = Queue()
		self.RECENT_ACTIVITIES = []
		self.FILTERED_ACTIVITIES = {
			'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
			'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
			'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
			'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
		}
		return self.flag



class GracefulKiller:
	kill_now = False
	def __init__(self):
		signal.signal(signal.SIGINT, self.exit_gracefully)
		signal.signal(signal.SIGTERM, self.exit_gracefully)

	def exit_gracefully(self, *args):
		self.kill_now = True


# {'eventid': 'cowrie.dos', 'type': 'TCP-SYN', 'timestamp': '1638547058.519988', 'protocol': 'TCP', 'src_ip': 'random', 'dst_ip': '172.17.0.2', 'src_mac': '02:42:ac:11:00:03', 'dst_mac': '02:42:ac:11:00:02', 'src_port': 'random', 'dst_port': 80}
config = open("config.json").read()
config = json.loads(config)
logfilepath = config['logfilepath']


# file append is atomic in usenix up to 4KB
def logevent(json_to_log):
	print ("[dos_detection]", json_to_log['type'], " detected -> log")
	# print ("write to log: ", json_to_log)
	try:
		json_txt = str(json.dumps(json_to_log))
		logfile = open( logfilepath, 'a')
		logfile.write( json_txt+"\n" ) 
		logfile.close()
	except Exception as e:
		raise e
	return 0



import os, sys

if __name__ == '__main__':

		sniffer = DOSdetect()

		if (sniffer.start()):
			print ("[dos_detection] initiated")	


		killer = GracefulKiller()
		while not killer.kill_now:
			# print ("dos detection running ... ", str(len(sniffer.RECENT_ACTIVITIES)))	
			# check if attacks have been detected
			for atype in sniffer.FILTERED_ACTIVITIES:
				if(sniffer.FILTERED_ACTIVITIES[atype]['flag']):
					
					data = sniffer.FILTERED_ACTIVITIES[atype]

					# [1638543414.0637527, ['TCP'], '52.7.58.13', '172.17.0.2', '02:42:ac:11:00:03', '02:42:ac:11:00:02', 14607, 80, None, None],
					tojson = {}
					tojson["eventid"] = "iotac.honeypot.dos"
					tojson["type"] = atype
					tojson["timestamp"] = str(sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][0])
					tojson["protocol"] = ",".join(sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][1])
					
					# check for random IPs used by sender
					random = True
					try:
						random = ( sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][2] != sniffer.FILTERED_ACTIVITIES[atype]["activities"][1][2] )
					except Exception as e:
						pass
					if(random):
						tojson["src_ip"] = "random"
					else:
						tojson["src_ip"] = sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][2]
					
					tojson["dst_ip"] = sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][3]
					tojson["src_mac"] = ",".join(data["attacker-mac"])
					tojson["dst_mac"] = sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][5]
			
					# check for random ports used by sender
					random = True
					try:
						random = ( sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][6] != sniffer.FILTERED_ACTIVITIES[atype]["activities"][1][6] )
					except Exception as e:
						pass
					if(random):
						tojson["src_port"] = "random"
					else:
						tojson["src_port"] = sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][6]

					tojson["dst_port"] = sniffer.FILTERED_ACTIVITIES[atype]["activities"][0][7]
			
					logevent( tojson )

					# remove case after writing to log
					sniffer.FILTERED_ACTIVITIES[atype] = {'flag': False, 'activities': [], 'attacker-mac': []}
				
			# only check every 5-60 seconds
			time.sleep( 5 )

		print ("")
		print ("[dos_detection] shutdown")	
		sniffer.stop()











