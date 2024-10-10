#!/bin/bash
sudo apt update -y
sudo apt updgrade -y
sudo apt install -y python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
