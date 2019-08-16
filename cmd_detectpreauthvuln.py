#!/usr/bin/python
#
# Link to the slides from Orange:
#   https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf
#
import os 
import re
import sys
import requests
import time
import datetime
import urlparse

def printhelp():
    
    print "Usage #1: ./cmd_detectpreauthvuln.py --hostfile=<HOSTSFILE>"
    print "\t --hostfile param: a file that holds list of hostnames / ipaddresses that the script will check"
    
    exit(0)    

def readfile(infile):
    
    hostfile = open(infile,"r")
    filedata=[]
    for line in hostfile.readlines():
        filedata.append(line.rstrip())    
    return filedata


def testVuln(url):

    testurl = url + "dana-na///css/ds.js"
    print "[*] Checking " + testurl
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0' }        
    response = requests.get(testurl,headers=headers,verify=False,timeout=30,allow_redirects=False)
    statuscode = response.status_code
    data = response.content
   
    if statuscode == 400:
        testurl = url + "dana-na///css/ds.js?/dana/html5acc/guacamole/"
        print "[*] Check 2, fetching " + testurl
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0' }        
        response = requests.get(testurl,headers=headers,verify=False,timeout=30,allow_redirects=False)
        statuscode = response.status_code
        data = response.content
        if statuscode == 200:
            print "\t[*] !!! Vulnerable URL: " + url + " !!!"
    else:
        print "[ ] Not vulnerable."
    

if __name__ == '__main__':
   
    if len(sys.argv) != 1 or sys.argv[1] == "--help":
        if sys.argv[1] == "--help":
            printhelp()
            exit(0)
    
    if '--hostfile=' in sys.argv[1]:
        hostfile = sys.argv[1].split("=")[1]
        hostfiledata = readfile(hostfile)


    for item in hostfiledata:
        url = "https://" + item + "/"
        print "[*] Testing " + url
        testVuln(url)

