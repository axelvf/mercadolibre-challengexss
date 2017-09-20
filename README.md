# Web Application XSS Scanner

## Installation using Docker:
For run the docker image, type the following command:
``` sh
docker run -i -t mercadolibre/challengexss:1.0
```

If you need build the docker image, run the script run_development.sh:
``` sh
./run_development.sh
```

## Manual installation: 

The tool works on Python 2.7 (2.7.13) and you should have mechanize and futures installed. 
If not installed, type the following in the terminal:
``` sh
pip install mechanize
pip install futures
```

or just:

``` sh
pip install requirements.txt
```

## Description: 

1) Short Scanning of links
2) If enable Comprehensive Scanning search for sub-domains
3) Process one link per thread
4) Checking every input on every page
5) If XSS found writes vulnerabilities on DB

## Usage: 

*_Basic:_ **python2 ./XssScanner.py https://xss-game.appspot.com/level1/frame (Set the absolute url)**  
*_Comprehensive Scan:_ **python2 ./XssScanner.py -u https://xss-game.appspot.com/level1/frame -e**  
*_Verbose logging:_ **python2 ./XssScanner.py -u https://xss-game.appspot.com/level1/frame -v** 
*_Cookies:_ **python2 ./XssScanner.py -u https://xss-game.appspot.com/level1/frame -c name=val name=val**
*_Threads:_ **python2 ./XssScanner.py -u https://xss-game.appspot.com/level1/frame -t 4**

## Test:
After run the docker image, the script loads a test with the following parameters:

``` sh
python2 ./XssScanner.py -v -u https://xss-game.appspot.com/level1/frame
```
