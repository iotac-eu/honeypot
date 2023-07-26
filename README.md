# IoTAC Honeypot
Honeypot component by Technische Universität Berlin.

# Version
3.0.1

# install and manage the docker
sudo docker pull jlnftk/honeypot:latest \
sudo docker run -p 2000-3000:22 --name iotac_honeypot -d -t jlnftk/honeypot:latest \
sudo docker ps \
sudo docker exec -it iotac_honeypot /bin/bash 

# running the honeypot
su honeypot \
cd $HOME/honeypot/code/modules/ \
## set kafka_topic and systemID in config.json
nano $HOME/honeypot/code/modules/config.json
bash start_honeypot.sh 

## observe the log
tail -f /home/honeypot/cowrie/var/log/cowrie/cowrie.log




## testing the honeypot from the outside
docker exec -it honeypot_attacker /bin/sh

## get honeypot IP
sudo docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(sudo docker ps -aq)

## run a portscan
nmap -v 172.17.0.2 -p 1-5000

## service login examples
ssh root@172.17.0.3 -p 22 
telnet 172.17.0.2 2223
ftp ...

## DoS
gcc synflood.c -o synflood
sudo ./synflood 172.17.0.2 22

## track activiy in the log
ssh root@172.17.0.2 -p 22 
execute commands

## trigger advanced detection (this will hit the entire network and will be detected by all honeypots as a shared threat)
docker exec -it honeypot_container1 /bin/sh
su honeypot
cd $HOME/honeypot/code/modules/

### setup IP of remote HP in config.json
bash start_honeypot.sh 

docker exec -it honeypot_container2 /bin/sh
su honeypot
cd $HOME/honeypot/code/modules/
### setup IP of remote HP in config.json
bash start_honeypot.sh 

### e.g. execute single port portscan across the network
nmap -v 172.17.0.0/24 -p 22


## read the API
curl -k https://172.17.0.2:5000/getall --header "apikey: iotacAPIkey1-s56JkyKbk4WrSBaXt9M99PC9XpGtUKZu9T"

## update the honeypot
su honeypot \
cd $HOME/honeypot/ \
git pull

## CREDs for honeypot user
thisisasecurepasswordforthehoneypotwithmanyletters

