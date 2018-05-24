#!/usr/bin/python

__author__='mkkeffeler'
#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.
import datetime
import dateutil.parser
import requests
import sys
import json
from optparse import OptionParser
import hashlib
import base64
import socket
from sqlalchemy import Column, Text, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import types
from sqlalchemy import exists
import dateutil.parser
from sqlalchemy.sql.expression import literal_column
import os
from configparser import ConfigParser
import getpass
import codecs

def dynamic_event_names(category,ip):   #Names the event based on what it is
    return str(ip) + " changed " + str(category) + " info on Shodan"
def dynamic_field_generator(key):   #Names the event based on what it is
    if (key == "domain"):
        return "cs1"
    if (key == "certificate"):
        return "cs2"
    if (key == "hostname"):
         return "cs3"
    if (key == "ports"):
        return "cs4"    
    if (key == "location"):
        return "cs5"
    if (key == "organization"):
        return "cs6"
    if (key == "vulns"):
        return "flexString1"
    if (key == "version"):
        return "flexString2"

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    parsed_date = dateutil.parser.parse(date_string).strftime("%b %d %Y %H:%M:%S")
    return parsed_date

def generate_cef_event(category,newdata,olddata,ip,upordown,ipdata,ordered):   #Called from other scripts to compile and completely generate the text for cef event
    message = ""
    event_name = str(dynamic_event_names(category,ip))
    data = json.loads(ipdata)
    if category == "vulns":
        inc_or_dec = ""
        remove_or_add = ""
        if (upordown == 1):
            inc_or_dec = "increased"
            remove_or_add = "added"
        else:
            inc_or_dec = "decreased"
            remove_or_add = "removed"
        message = "Shodan has "  + inc_or_dec +  " the # of vulns. The Vuln " + remove_or_add + " was " + str(newdata)
        cef = 'CEF:0|Shodan Tools|Zone Monitoring|1.0|100|' + event_name + '|1|' + ' end='+ str(date_parse(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))) +' src=' + str(ip) + ' msg=' + message + " "
    else:
        message = "Shodan previously listed ip " + str(ip) + " " + str(category) + " as " + str(olddata) + " and now lists it as " + str(newdata)
        cef = 'CEF:0|Shodan Tools|Zone Monitoring|1.0|100|' + event_name + '|1|' + ' end='+ str(date_parse(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))) +' src=' + str(ip) + ' msg=' + message + " "
    cef += str(dynamic_field_generator(str(ordered[0]))) + '='
    print("DONE1")
    cef += data[str(ordered[0])] + ' '
    print("DONEMID")
    cef += str(dynamic_field_generator(str(ordered[1]))) + '=' + data[str(ordered[1])]  + ' ' + str(dynamic_field_generator(str(ordered[2]))) + '=' + data[str(ordered[2])]+ ' ' + str(dynamic_field_generator(str(ordered[3]))) + '='
    print("DONE2")
    cef += data[str(ordered[3])]+ ' ' + str(dynamic_field_generator(str(ordered[4]))) + '=' + data[str(ordered[4])]+ ' ' + str(dynamic_field_generator(str(ordered[5]))) + '=' + data[str(ordered[5])]+ ' ' + str(dynamic_field_generator(str(ordered[8]))) + '=' + data[str(ordered[8])]+ ' ' + str(dynamic_field_generator(str(ordered[7]))) + '=' + data[str(ordered[7])]
    cef += " cs1Label=Domain cs2Label=Certificate cs3Label=Hostnames cs4Label=Ports cs5Label=Location cs6Label=Organization flexString1Label=Vulnerabilties flexString2Label=Version"
    
    return cef
def generate_cef_event_arcsight_list(ip,ordered,data):   #Called from other scripts to compile and completely generate the text for cef event
    print ("HERE")
    data = json.loads(data)
    message = ""
    event_name = "Shodan Results: " + str(ip)
    print("IN CEF")
    cef = 'CEF:0|Shodan Tools|Zone Monitoring|1.0|100|'
    print("MIDDONE")
    cef += event_name + '|1|' + ' src=' + str(ip) + ' end='
    print("MIDDONE2")
    cef += str(date_parse(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))) +' '
    print("DONE112")
    cef += str(dynamic_field_generator(str(ordered[0]))) + '='
    print("DONE1")
    cef += data[str(ordered[0])] + ' '
    print("DONEMID")
    cef += str(dynamic_field_generator(str(ordered[1]))) + '=' + data[str(ordered[1])]  + ' ' + str(dynamic_field_generator(str(ordered[2]))) + '=' + data[str(ordered[2])]+ ' ' + str(dynamic_field_generator(str(ordered[3]))) + '='
    print("DONE2")
    cef += data[str(ordered[3])]+ ' ' + str(dynamic_field_generator(str(ordered[4]))) + '=' + data[str(ordered[4])]+ ' ' + str(dynamic_field_generator(str(ordered[5]))) + '=' + data[str(ordered[5])]+ ' ' + str(dynamic_field_generator(str(ordered[8]))) + '=' + data[str(ordered[8])]+ ' ' + str(dynamic_field_generator(str(ordered[7]))) + '=' + data[str(ordered[7])]
    cef += " cs1Label=Domain cs2Label=Certificate cs3Label=Hostnames cs4Label=Ports cs5Label=Location cs6Label=Organization flexString1Label=Vulnerabilties flexString2Label=Version"
    return cef




