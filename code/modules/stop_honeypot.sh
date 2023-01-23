#!/bin/sh
echo "[IoTAC HP] stopping honeypot"
sudo $HOME/cowrie/bin/cowrie stop
echo "[IoTAC HP] stopping detection modules and API"
sudo pkill python

echo "[IoTAC HP] done."