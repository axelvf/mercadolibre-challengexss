#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author axelv@squez.com.ar

Script that performs basic scan and find XSS vulnerabilities in a concurrent way and persist them into a SQLite DB
"""

import mechanize
from multiprocessing import cpu_count
import argparse
import logging
import sqlite3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Payloads to check
payloads = [
    '<script>confirm(1)</script>',
    '<svg onload=confirm(1)>',
    '<script>alert(1);</script>',
    '<script>alert(1)</script>',
    '<h1><font color=blue>hellox worldss</h1>',
    '%22%3Cscript%3Ealert%28%271%27%29%3C%2Fscript%3E',
    '<BODY ONLOAD=alert("hellox worldss")>',
    '<input onfocus=write(XSS) autofocus>',
    '<input onblur=write(XSS) autofocus><input autofocus>',
    '<body onscroll=alert(XSS)><br><br><br><br><br><br>...<br><br><br><br><input autofocus>'
]

# Elements to discard
blacklist = [
    '.png',
    '.jpg',
    '.jpeg',
    '.mp3',
    '.mp4',
    '.avi',
    '.gif',
    '.svg',
    '.pdf'
]

# Logger initialization
logger = logging.getLogger(__name__)
lh = logging.StreamHandler()
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)

# Browser initialization
browser = mechanize.Browser()
browser.addheaders = [(
    'User-agent',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.30 (KHTML, like Gecko) Ubuntu/11.04 Chromium/12.0.742.112 Chrome/12.0.742.112 Safari/534.30'
)]
browser.set_handle_robots(False)
browser.set_handle_refresh(False)
# Follows refresh 0 but not hangs on refresh > 0
browser.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
# Want debugging messages?
browser.set_debug_http(False)
browser.set_debug_redirects(False)
browser.set_debug_responses(False)

# Setting command line argument parser
parser = argparse.ArgumentParser()
parser.add_argument('-u', action='store', dest='url',
                    help='The URL to analyze')
parser.add_argument('-t', action='store', dest='threads',
                    help='The maximum number of thread to process')
parser.add_argument('-e', action='store_true', dest='is_comprehensive',
                    help='Enable comprehensive scan')
parser.add_argument('-v', action='store_true', dest='verbose',
                    help='Enable verbose logging')
parser.add_argument('-c', action='store', dest='cookies',
                    help='Space separated list of cookies',
                    nargs='+', default=[])

# Script arguments
args = parser.parse_args()

# Sets logger level
logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

# Initialize DB connection
conn = sqlite3.connect("vulnerabilities.db", check_same_thread=False)
cursor = conn.cursor()
# Creates a table if not exists
cursor.execute('CREATE TABLE IF NOT EXISTS xss (link TEXT, payload TEXT, element TEXT)')


def get_links():
    """
    Gets all domain to scan
    :return: All domain
    """
    url = str(args.url)
    if not url:  # if the url has been passed or not
        logger.log(logging.ERROR, 'Url not provided correctly')
        return []

    small_url = re.sub('^http(s)?://(www\.)?', '', url)
    sub_domains = [url]  # list of domains

    logger.log(logging.INFO, 'Doing a short traversal.')
    try:
        browser.open(url)
        for cookie in args.cookies:
            logger.log(logging.INFO, 'Adding cookie: %s' % cookie)
            browser.set_cookie(cookie)
        browser.open(url)
        logger.log(logging.INFO, 'Finding all the links of the website ' + str(url))
        for link in browser.links():  # finding the links of the website
            if small_url in str(link.absolute_url):
                sub_domains.append(str(link.absolute_url))
        sub_domains = list(set(sub_domains))
    except Exception as e:
        logger.log(logging.ERROR, 'Error while adding links of the website:' + str(url), str(e))

    logger.log(logging.INFO, 'Number of links to test are: ' + str(len(sub_domains)))

    # 2) If enable Comprehensive Scanning search for sub-domains
    sub_domains = set_comprehensive_search(small_url, sub_domains)
    return sub_domains


def set_comprehensive_search(url, sub_domains):
    """
    Check if comprehensive search is enable and add sub-domains
    :param url: The URL given
    :param sub_domains: The list of sub-domains
    :return: A list of sub-domains
    """
    if args.is_comprehensive:
        logger.log(logging.INFO, 'Doing a comprehensive traversal. This may take a while')
        comprehensive_urls = []
        for link in sub_domains:
            try:
                browser.open(link)
                # going deeper into each link and finding its links
                for new_link in browser.links():
                    if url in str(new_link.absolute_url):
                        comprehensive_urls.append(new_link.absolute_url)
            except Exception as e:
                logger.log(logging.ERROR, 'Error while adding comprehensive search:' + str(link), str(e))

        sub_domains = list(set(sub_domains + comprehensive_urls))
        logger.log(logging.INFO, 'Total Number of links to test have become: ' + str(len(sub_domains)))
    return sub_domains


def process_links():
    """
    Process all the links finding XSS vulnerabilities
    :return:
    """
    logger.log(logging.INFO, 'Start processing links')
    if links:
        # Get the max number of workers
        max_workers = cpu_count() if args.threads is None else args.threads
        pool = ThreadPoolExecutor(max_workers)
        futures = [pool.submit(find_xss, link) for link in links]
        for r in as_completed(futures):
            if r.result() is not None:
                logger.log(logging.ERROR, "Error processing worker: " + str(r))
    else:
        logger.log(logging.INFO, '\tNo link found, exiting')


def find_xss(link):
    """
    Search for XSS vulnerabilities and persist them on DB
    :param link: Link given
    :return:
    """
    xss_links = []
    blacklisted = False
    y = str(link)
    logger.log(logging.DEBUG, str(link))
    for ext in blacklist:
        if ext in y:
            logger.log(logging.DEBUG, '\tNot a good url to test')
            blacklisted = True
            break
    if not blacklisted:
        try:
            browser.open(str(link))  # open the link
            if browser.forms():  # if a form exists, submit it
                for item in payloads:
                    params = list(browser.forms())[0]  # our form
                    browser.select_form(nr=0)  # submit the first form
                    for param in params.controls:
                        par = str(param.__str__)
                        # submit only those forms which require text
                        if 'TextControl' in par:
                            logger.log(logging.DEBUG, '\tParam to test: ' + str(param.name))
                            # 4) Checking every input on every page
                            test_payload(item.encode('utf-8'), param, link, xss_links)
                # 5) If XSS found writes vulnerabilities on DB
                persist_vulnerabilities(xss_links)
        except Exception as e:
            # logger.log(logging.ERROR, str(e))
            pass


def test_payload(payload, param, link, xss_links):
    """
    Test vulnetabilities with an specific payload
    :param payload: The payload
    :param param: The element
    :param link: The link
    :return:
    """
    try:
        browser.form[str(param.name)] = payload
        browser.submit()
        # if payload is found in response, we have XSS
        if payload in browser.response().read():
            report = 'Link: %s, Payload: %s, Element: %s' % (str(link), payload, str(param.name))
            logger.log(logging.DEBUG, 'Report XSS found! ' + report)
            xss_links.append((str(link), payload, str(param.name)))
        browser.back()
    except Exception as e:
        '''logger.log(logging.ERROR, 'Error testing Link: %s, Payload: %s, Element: %s'
                    % (str(link), payload, str(param.name)), str(e)) '''
        pass


def persist_vulnerabilities(xss_links):
    """
    Persist as many XSS vulnerabilities on DB
    :param xss_links:
    :return:
    """
    try:
        if xss_links:
            cursor.executemany('INSERT INTO xss VALUES (?,?,?)', xss_links)
            conn.commit()
    except Exception as e:
        logger.log(logging.ERROR, 'Error while persisting on database:' + str(xss_links), str(e))


# main process
# 1) Short Scanning of links
links = get_links()
# 3) Process one link per thread
process_links()
