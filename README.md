# Web Application XSS Scanner

## Installation: 

The tool works on Python 2.7 and you should have mechanize and futures installed. 
If not installed, type the following in the terminal:

1. **pip install mechanize**
2. **pip install futures**

or just:

1. **pip install requirements.txt** 

## Description: 

1) Short Scanning of links
2) If enable Comprehensive Scanning search for sub-domains
3) Process one link per thread
4) Checking every input on every page
5) If XSS found writes vulnerabilities on DB


## Usage: 

*_Basic:_ **XssScanner.py https://xss-game.appspot.com/level1/frame (Set the absolute url)**  
*_Comprehensive Scan:_ **python XssScanner.py -u https://xss-game.appspot.com/level1/frame -e**  
*_Verbose logging:_ **python XssScanner.py -u https://xss-game.appspot.com/level1/frame -v** 
*_Cookies:_ **python XssScanner.py -u https://xss-game.appspot.com/level1/frame -c name=val name=val**
*_Threads:_ **python XssScanner.py -u https://xss-game.appspot.com/level1/frame -t 4**
