#!/bin/sh

while true; do
    read -p "Do you want to run test program? (y/n)" yn
    case $yn in
        [Yy]* ) python2 XssScanner.py -v -u https://xss-game.appspot.com/level1/frame; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer y (yes) or n (no).";;
    esac
done
