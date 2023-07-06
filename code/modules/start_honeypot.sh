#!/bin/bash
printf "[IoTAC HP] update honeypot and check install ..."
git pull

rm honeypot.log
rm $HOME/cowrie/var/log/cowrie/cowrie.json
touch $HOME/cowrie/var/log/cowrie/cowrie.json

source $HOME/cowrie/honeypot-env/bin/activate

# dirty fix for missing dependencies
pip install confluent-kafka
pip install file-read-backwards

printf "[IoTAC HP] initiate honeypot core ..."
$HOME/cowrie/bin/cowrie start
printf "\\n"

sleep 1
printf "[IoTAC HP] initiate DoS detection ..."
nohup sudo python3 -u dos.py >> honeypot.log &
printf "\\n"

sleep 1
printf "[IoTAC HP] initiate portscan detection ..."
sudo python3 -u portscans.py -d >> honeypot.log &
printf "\\n"

sleep 1
printf "[IoTAC HP] initiate advanced detection with network peers..."
python3 -u advanced_detection.py -d >> honeypot.log &
printf "\\n"

sleep 1
printf "[IoTAC HP] publish API to network peers"
nohup python3 -u publishAPI.py >> honeypot.log &
printf "\\n"

sleep 1
printf "[IoTAC HP] start kafka connection"
nohup python3 -u pushAPI.py >> honeypot.log &
printf "\\n"

#read  -n 1 -p "Press enter to tail honeypot log or ctrl+c to quit"
#clear

reset
echo "[IoTAC HP] Honeypot initiated."
echo "tail -f $HOME/cowrie/var/log/cowrie/cowrie.json"
# tail has some issues to follow the file since its async written

