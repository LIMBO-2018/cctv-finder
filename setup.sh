#!/bin/bash

echo "Installing CCTV Finder Tool dependencies..."
pkg update -y
pkg install -y python nmap
pip install requests

echo "Setting up CCTV Finder Tool..."
chmod +x cctv.py

echo "Installation complete! Run the tool with: python cctv.py"
