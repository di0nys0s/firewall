
#! python
"""
firewal.py will scan the logfile for authentification tryout on ssh port 
and add it to arno firewall custom rules 
"""
import re
import sys
from ipwhois import IPWhois
"""
Variables :
logfilename : the auth.log file path
firefilename : the arno firewall custom file path 
"""

logfilename='/var/log/auth.log'
firefilename='/etc/arno-iptables-firewall/custom-rules'

# The arno firewall custum file will be scanned to 
oldiplist=[]
with open(firefilename) as f:
    for line in f:
        m = re.findall('([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)', line)
        inlist=False
        if m:
            for i in range(len(oldiplist)):
                if ( m[0] == oldiplist[i] ):
                    inlist=True
            if inlist:
                print('already in list')
            else:
                print('Not in list')
                oldiplist.append(m[0])

iplist=[]
with  open(logfilename) as f:
    for line in f:
        #print(line)
        m = re.findall('([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)', line)
        inlist=False
        if m:
            for i in range(len(iplist)):
                if ( m[0] == iplist[i] ):
                    inlist=True
            for i in range(len(oldiplist)):
                if ( m[0] == oldiplist[i] ):
                    inlist=True
            if inlist:
                print('already in list')
            else:
                print('Not in list')
                iplist.append(m[0])
print(iplist)
import subprocess
for i in range(len(iplist)):
    obj = IPWhois(iplist[i])
    results = obj.lookup_rdap(depth=1)
    if results['asn_country_code'] == 'CA' or results['asn_country_code'] == 'US':
        subprocess.call(["whois", iplist[i]])
        print('['+str(i)+'/'+str(len(iplist))+'] Do you want to block '+ iplist[
i]+' ? ')
        rep = input()
        if rep == '' or  rep == 'y' or  rep == 'yes' or  rep == 'Y' :
            print('will have to block it !')
            with open(firefilename, "a") as myfile:
                myfile.write("\niptables -A INPUT -s "+iplist[i]+"/24 -j REJECT"
)
    else:
        print('Not Canada or USA ('+results['asn_country_code']+'), blocking '+iplist[i]
)
        with open(firefilename, "a") as myfile:
            myfile.write("\niptables -A INPUT -s "+iplist[i]+"/24 -j REJECT")
    #subprocess.call(["whois", iplist[i]])
    #print('['+str(i)+'/'+str(len(iplist))+'] Do you want to block '+ iplist[i]+
' ? ')
    #rep = input()
    #if rep == '' or  rep == 'y' or  rep == 'yes' or  rep == 'Y' :
    #    print('will have to block it !')
    #    with open(firefilename, "a") as myfile:
    #        myfile.write("\niptables -A INPUT -s "+iplist[i]+"/24 -j REJECT")


