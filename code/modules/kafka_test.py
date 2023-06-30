"""
KAFKA
"""

from confluent_kafka import Producer
import socket
from datetime import datetime
import json
import uuid

conf = {'bootstrap.servers': "116.203.5.132:9092", 'client.id': socket.gethostname()}
producer = Producer(conf)

def push_report(producer, report):
   now = datetime.now()  # current date and time
   date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

   dict_report = {
                 "dataSourceID": "IoTAC_HP_DRONE",
                 "systemID": "DRONE_Test",
                 "reportType": "HP-Threat-Report",
                 "_timestamp": date_time,
                 "location": {
                   "geoLocation": {
                     "latitude": 46.953879,
                     "longitude": 17.870395
                   },
                   "virtualLocation": "AIRBUS_OTTOBRUNN"
                 },
                 "value": {
                   "type": "Honeypot",
                   "monitoredAssetID": ["Drone1"],
                   "monitoredAssetIP": ["192.168.0.20"],
                   "measurement": [{
                       "Name": "AttackType",
                       "value": "GPSSpoofing"
                     }, {
                       "Name": "attackProbability",
                       "value": "22"
                     }
                   ],
                   "requestSource": "22",
                   "_timestamp": date_time
                 }
               }

   #report["timestamp"] = date_time
   json_send = json.dumps(dict_report).encode()
   producer.produce("IOTAC.HP.RMS", key=str(uuid.uuid4()), value=json_send)
   producer.flush()
   print("Reported to Kafka")

push_report(producer, "")
