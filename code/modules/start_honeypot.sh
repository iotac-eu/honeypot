#!/bin/sh

rm honeypot.log
rm /home/cowrie/cowrie/var/log/cowrie/cowrie.json
touch /home/cowrie/cowrie/var/log/cowrie/cowrie.json

$HOME/cowrie/bin/cowrie start

sleep 1
nohup sudo python3 -u dos.py >> honeypot.log &

sleep 1
sudo python3 portscans.py -d >> honeypot.log &

sleep 1
python3 advanced_detection.py -d >> honeypot.log &

sleep 1
nohup python3 publishAPI.py >> honeypot.log &

# tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json 
# tail has some issues to follow the file since its async written


