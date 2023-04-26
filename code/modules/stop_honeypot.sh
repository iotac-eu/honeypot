#!/bin/sh
echo "[IoTAC HP] stopping honeypot"
sudo $HOME/cowrie/bin/cowrie stop
echo "[IoTAC HP] stopping detection modules and API"
sudo pkill python

rm $HOME/code/modules/honeypot.log

echo "[IoTAC HP] done."