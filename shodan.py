__author__ = "mkkeffeler"
#Script that gets provided list of zones to check against Shodan
#On first run, it will run all IPs and save them in a CSV file, no events generated
#Subsequently, it will check that file and requery all IPs in the zone and compare to determine changes.
#Any changes that are made, get updated in the CSV file and generate a cef event as shown on line 164
#Usage: python shodan.py (no parameters can be provided at this point)
#Future updates: This is somewhat memory intensive, we could save the data of an IP address individually
#rather than doing them all, and saving at the end. 
#Future Update 2: Move api key to config file or find another way to store potentially multiple.

import requests
import sys
import ipaddress
from configparser import ConfigParser
import dateutil.parser
from pprint import pprint
from netaddr import *
import json
import os
import time
import csv
from tempfile import NamedTemporaryFile
import shutil
from submit_event import generate_cef_event,which_field

api_key = '' #Might be best to have 2-3 keys here if we are doing lots of zones

def Port_list(shodan):
    message = ""
    for port in shodan['ports']:
       message += str(port) + " "
    if (message == ""):
        return "No Historical Port Information."
    else:
        return message
def hostname_list(shodan):
    message = ""
    for hostname in shodan['hostnames']:
       message += str(hostname) + " "
    if (message == ""):
        return "No Historical Hostname Information."
    else:
        return message
def certificate_status(shodan):
    message = ""
    if "ssl" in shodan.keys():
        if "cert" in shodan['ssl'].keys():
            return "Certificate Expired: " + str(shodan['ssl']['cert']['expired'])
    else:
        return "Certificate Unknown."

def check_org(shodan):
    message = ""
    if "org" in shodan.keys():
        return str(shodan['org'])
    else:
        return "No Organization Listed"

def check_time(shodan):
    message = ""
    if "timestamp" in shodan['data'][0].keys():
        return str(dateutil.parser.parse(str(shodan['data'][0]['timestamp'])).strftime("%x"))
    else:
        return "No Updated Time Available."

def check_asn(shodan):
    message = ""
    if "asn" in shodan.keys():
        return str(shodan['asn'])
    else:
        return "No ASN Provided."

def domain_list(shodan):
    message = ""
    for domain in shodan:
        message += str(domain) + " "
    if (message == ""):
        return "No Historical Domain Name Information."
    else:
        return message
def warn_and_exit(msg):
    print('Error:')
    print(msg)
    exit()

def is_private_or_null(ip):  #Offloaded this function
    try:
        parsed_ip = ipaddress.ip_address(ip)
        if parsed_ip.is_private:
            return 1
        else:
            return 0
    except Exception as ex:
        warn_and_exit(str(ex))
    if ip == "":
        warn_and_exit("There was no IP address provided on execution")
#This function can be passed a filename and will open the csv file with information on that zone
#Then will load it into a dictionary for our use and pass the dict back
def zone_file_to_dict(zone):

    zone_info = {}
    parts = zone.split(".")
    last = parts[3].split("/")[0]
    if os.path.isfile(parts[0]+parts[1]+parts[2]+last+".csv"):
        ifile = open(parts[0]+parts[1]+parts[2]+last+".csv","r")
        file = csv.reader(ifile)
        for line in file:
          #  print line
            zone_info[line[0]] = {}

            zone_info[line[0]]["location"] = line[5]
            zone_info[line[0]]["certificate"] = line[2]
            zone_info[line[0]]["ports"] = line[4]
            zone_info[line[0]]["organization"] = line[6]
            zone_info[line[0]]["domain"] = line[1]
            zone_info[line[0]]["ASN"] = line[7]
            zone_info[line[0]]["hostname"] = line[3]


    return zone_info
#This function takes a dictionary, and writes it out to a zone file in CSV format
def dict_to_zone_file(zonedict,zone):
    cur_details = []
    parts = zone.split(".")
    last = parts[3].split("/")[0]
    file = open(parts[0]+parts[1]+parts[2]+last+".csv","w")
    writer = csv.writer(file, delimiter=',',quoting=csv.QUOTE_ALL)
    for ip in zonedict:
        line = [ip]
        for detail in zonedict[ip]: #for every element in this row
            line.append(zonedict[ip][detail]) #Now append new data in where it should be
        writer.writerow(line)
#Used to update the csv zone file, and report that there was a change to the zone file
def update_and_report(zonelength,ip,zone,linenumber,key_changed,newdata,olddata,updatedindex):
   # print "WE IN HERE"
    row_count = zonelength
    parts = zone.split(".")
    last = parts[3].split("/")[0]
    filename = parts[0]+parts[1]+parts[2]+last+".csv"
    tempfile = NamedTemporaryFile(delete=False)
    linecount = 0
    with open(parts[0]+parts[1]+parts[2]+last+".csv", 'rb') as csvFile, tempfile:
        reader = csv.reader(csvFile, delimiter=',')
        writer = csv.writer(tempfile, delimiter=',')
      #  row_count = sum(1 for row in reader) # fileObject is your csv.reader
     #   print str((row_count - linenumber))
        for row in reader:
        #    print "ROWSSSS"
            if linecount != (row_count - linenumber - 1):  #If the row we are looking at is not the one we need to update
                writer.writerow(row)
         #       print "FOUND THE LINE"
                linecount += 1
            else: #Now we have the row we need to edit
                line = []
                index = 0
                for detail in row: #for every element in this row
                    if index != updatedindex: #If this element is not at the index of the one to be updated, write it to list
                        line.append(detail)
                        index += 1
                    else:
                        line.append(newdata) #Now append new data in where it should be
                        index += 1
                writer.writerow(line) #Write the row
                linecount += 1
    shutil.move(tempfile.name, filename) #Move temp file to permanent, don't want to read and write to same file
    event = generate_cef_event(key_changed,newdata,olddata,ip) #Generate a cef event for this change
    print (event)
 #   syslog(event)

    return
 
if __name__ == "__main__":
    config = ConfigParser()
    config.read('config.ini')
    config_zones = config.get('DEFAULT','zones')
    config_zones = config_zones.split(",")
    zones = config_zones
   #List of zones to be checked
    for zone in zones:  #for every zone
        linenumber = 0
        previousstate = zone_file_to_dict(zone) #Check if we have done this zone before, if so load up the previous results
        if previousstate != {}: #If we have done this zone once before, then we should check everything. 
            for ip in IPNetwork(zone): #For all IPs in this zone
                zonelength = len(IPNetwork(zone))
                if (is_private_or_null(ip) == 0):  #If its private or empty, seems useless to check
                    parsed_ip = ip
                    time.sleep(1) #Can't check against Shodan more than 1 time per second
                    response = requests.get('https://api.shodan.io/shodan/host/%s?key=%s' % (str(parsed_ip), api_key))
                    print ("IP: " + str(parsed_ip))
                    try:
                        shodan= response.json()

                        if 'data' in shodan.keys(): #if we got data back, check that it doesn't conflict
                            if str(shodan['data'][0]['location']['country_name']) != previousstate[str(ip)]["location"]:
                                update_and_report(zonelength,str(ip),zone,linenumber,"location",str(shodan['data'][0]['location']['country_name']),previousstate[ip]["location"],5)

                            hostnames = hostname_list(shodan).split(" ")
                            for hostname in hostnames:
                                if hostname not in previousstate[str(ip)]["hostname"]:
                                    update_and_report(zonelength,str(ip),zone,linenumber,"hostname",hostname_list(shodan),previousstate[str(ip)]["hostname"],3)

                            domains = domain_list(shodan['data'][0]['domains']).split(" ")
                            for domain in domains:
                                if domain not in previousstate[str(ip)]["domain"]:
                                    update_and_report(zonelength,str(ip),zone,linenumber,"domain",domain_list(shodan['data'][0]['domains']),previousstate[str(ip)]["domain"],1)

                            if certificate_status(shodan['data'][0]) != previousstate[str(ip)]["certificate"]:
                                update_and_report(zonelength,str(ip),zone,linenumber,"certificate",certificate_status(shodan['data'][0]),previousstate[str(ip)]["certificate"],2)

                            if check_asn(shodan) != previousstate[str(ip)]["ASN"]:
                               # print "1: " + check_asn(shodan) + "2 " + previousstate[str(ip)]["ASN"]
                                update_and_report(zonelength,str(ip),zone,linenumber,"ASN",check_asn(shodan),previousstate[str(ip)]["ASN"],7)

                            if check_org(shodan) != previousstate[str(ip)]["organization"]:
                                update_and_report(zonelength,str(ip),zone,linenumber,"organization",check_org(shodan),previousstate[str(ip)]["organization"],6)
                            
                            ports = Port_list(shodan).split(" ")
                            for port in ports:
                             if port not in previousstate[str(ip)]["ports"]:
                                update_and_report(zonelength,str(ip),zone,linenumber,"ports",Port_list(shodan),previousstate[str(ip)]["ports"],4)
                        else: #Otherwise it was an empty results or we had some other error, no reports should be made
                            print(shodan['error'])
                        linenumber += 1
                    except:
                        continue
        else: #Otherwise, lets just store everything the first time so we can set a base case
            new_baseline = {}
            for ip in IPNetwork(zone):
                    if (is_private_or_null(ip) == 0):
                        time.sleep(1)
                        parsed_ip = ip
                        response = requests.get('https://api.shodan.io/shodan/host/%s?key=%s' % (str(parsed_ip), api_key))
                        print ("IP: " + str(parsed_ip))
                        new_baseline[str(ip)] = {}
                        try:
                            shodan= response.json()
                            if 'data' in shodan.keys(): #Fill in all the info and continue
                                new_baseline[str(ip)]["location"] = str(shodan['data'][0]['location']['country_name'])
                                new_baseline[str(ip)]["hostname"] = hostname_list(shodan) 

                                new_baseline[str(ip)]["domain"] = domain_list(shodan['data'][0]['domains'])
                                new_baseline[str(ip)]["certificate"] = certificate_status(shodan['data'][0])
                                new_baseline[str(ip)]["ASN"] = check_asn(shodan)
                                new_baseline[str(ip)]["organization"] = check_org(shodan)
                                new_baseline[str(ip)]["ports"] = Port_list(shodan)
                            else: #If this IP does not have info on it fill in N/A
                                print(shodan['error'])
                                new_baseline[str(ip)]["location"] = "N/A"
                                new_baseline[str(ip)]["hostname"] = "N/A"
                                new_baseline[str(ip)]["domain"] = "N/A"
                                new_baseline[str(ip)]["certificate"] = "N/A"
                                new_baseline[str(ip)]["ASN"] = "N/A"
                                new_baseline[str(ip)]["organization"] = "N/A"
                                new_baseline[str(ip)]["ports"] = "N/A"
                        except:
                            continue
            dict_to_zone_file(new_baseline,zone) #Write this to the file
