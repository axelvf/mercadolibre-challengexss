#!/bin/sh

while true; do
    read -p "Do you want to run test program? (y/n) \n the test will run python2 ./XssScanner.py -v -u https://xss-game.appspot.com/level1/frame" yn
    case $yn in
        [Yy]* ) echo "Running python2 ./XssScanner.py -v -u https://xss-game.appspot.com/level1/frame";python2 ./XssScanner.py -v -u https://xss-game.appspot.com/level1/frame; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer y (yes) or n (no).";;
    esac
done
