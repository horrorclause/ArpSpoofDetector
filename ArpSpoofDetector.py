""" Checks if your machine is being attacked via MitM via ARP spoof. """

import os
import re
import itertools


broadcastAdd = 'ff-ff-ff-ff-ff-ff'
holding = []
duplicates = []


# Gets the ARP table from a Windows Machine
def getARP():
    arpData = []
    with os.popen('arp -a') as f:
        for i in f.readlines():
            arpData.append(i)
    return arpData
#print(getARP())

# Uses Regex to iterate through getARP() data and create a new
# list of the correct IP and MAC pairs, with no empty lists
def regIpMac(data):
    ipAndMac = []  # Stores the paired IP and MAC
    for line in data:
        ip = re.findall(r"(?:\d{1,3}\.)+(?:\d{1,3})", line)  # Regex for IP address
        mac = re.findall(r"(?:\w{1,2}\-)+(?:\w{1,2})", line)  # Regex for MAC
        if len(ip) and len(mac) > 0:  # Checks to make sure the ip and max regex have contents
            # TODO: check if they are broadcast addresses and exclude if they are
            # Creates a list of the Ip , Mac in the parent list ipAndMac
            ipAndMac.append([ip[0],mac[0]])
        else:
            continue
    return ipAndMac
#print(regIpMac(getARP()))

correctData = regIpMac(getARP())

"""Need to run loop twice to catch all instance of broadcast add. Not sure why.
    correctData is sanitized of Broadcast Adds."""
for i in correctData:
    for x in i:
        if x == broadcastAdd:
            correctData.remove(i)

for i in correctData:
    for x in i:
        if x == broadcastAdd:
            #print(i)
            correctData.remove(i)

#for i in correctData:
    #print(i)

"""Need to separate duplicates from uniques"""
for i in correctData:
    if i not in holding:  # Separates unique addresses
        holding.append(i)
    else:
        duplicates.append(i)  # Separates duplicated addresses
#print('***----------------***')
#print(duplicates)
#print('***----------------***')
#print(holding)


"""Sorts and dedupes the Duplicates list, and prints out duped machines."""

print('\nThe following machines are being spoofed:')
print('+'+(len('The following machines are being spoofed: ')*'=') + '+')
duplicates.sort()
for x in list(duplicates for duplicates,_ in itertools.groupby(duplicates)):  # Sorts duplicates and dedupes
    print('IP: {}'.format(x[0]))
    print('MAC: {}'.format(x[1]))
    print('***'+(len(x[1])*'-')+'***')



