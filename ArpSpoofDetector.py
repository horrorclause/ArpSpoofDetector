""" Checks for duplicate MAC addresses, displays them and outputs to a text file.
    Could be an indicator of a MitM attack."""

import os, platform, re
import itertools
import datetime


broadcastAdd = 'ff-ff-ff-ff-ff-ff'
holding = []
duplicates = []


# Gets the ARP table from a Windows Machine
def getARP():
    try:
        if platform.system() == 'Windows':
            arpData = []
            with os.popen('arp -a') as f:
                for i in f.readlines():
                    arpData.append(i)
            return arpData
    except Exception:
        print('This is not a windows machine')

# Uses Regex to iterate through getARP() data and create a new
# list of the correct IP and MAC pairs, with no empty lists
def regIpMac(data):
    ipAndMac = []  # Stores the paired IP and MAC
    for line in data:
        ip = re.findall(r"(?:\d{1,3}\.)+(?:\d{1,3})", line)  # Regex for IP address
        mac = re.findall(r"(?:\w{1,2}\-)+(?:\w{1,2})", line)  # Regex for MAC
        if len(ip) and len(mac) > 0:  # Checks to make sure the IP and MAC regex have contents
            ipAndMac.append([ip[0],mac[0]])  # Creates a list of the Ip & MAC in ipAndMac[]
        else:
            continue
    return ipAndMac

correctData = regIpMac(getARP())  #Gets the ARP table and parses it

# TODO:Need to run loop twice to catch all instance of broadcast add. Not sure why.
#      correctData should be sanitized of Broadcast Adds.
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


for i in correctData:
    if i not in holding:  # Separates unique addresses
        holding.append(i)
    else:
        duplicates.append(i)  # Separates duplicated addresses

duplicates.sort()

print('\nThe following machines are being spoofed:')
print('+'+(len('The following machines are being spoofed: ')*'=') + '+')
# Dedupes the Duplicates list, and prints out duped machines.
for x in list(duplicates for duplicates,_ in itertools.groupby(duplicates)):  # Sorts duplicates and dedupes
    print('IP: {}'.format(x[0]))
    print('MAC: {}'.format(x[1]))
    print('***'+(len(x[1])*'-')+'***')

# Exports ARP data as file w/Date & Time
def arpFile():
    currentTime = datetime.datetime.now().strftime("%m-%d-%Y %H.%M.%S")
    fileName = 'Duplicated Mac & IP addresses {}.txt'.format(currentTime)
    file = open(fileName, 'a')
    file.write('### - {} - ###\n'.format(currentTime))
    file.write('######'+(len(currentTime)*'#')+'######\n')

    for x in list(duplicates for duplicates, _ in itertools.groupby(duplicates)):  # Sorts duplicates and dedupes
        file.write('IP: {}\n'.format(x[0]))
        file.write('MAC: {}\n'.format(x[1]))
        file.write('***' + (len(x[1]) * '-') + '***\n')
        file.flush()
    file.close()

    print('\nThis file saved as: {}'.format(fileName))
    print('To this directory: {}'.format(os.getcwd()))

arpFile()