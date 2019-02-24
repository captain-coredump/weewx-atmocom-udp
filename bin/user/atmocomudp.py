#!/usr/bin/env python
# Copyright 2017-2019 Arthur Emerson, vreihen@yahoo.com
# Distributed under the terms of the GNU Public License (GPLv3)

from __future__ import with_statement
import math
import time
import weewx.units
import weedb
import weeutil.weeutil
import weewx.drivers
import weewx.wxformulas
from weeutil.weeutil import tobool
import syslog
import threading

import sys, getopt
from socket import *
#import json
#from collections import namedtuple
import datetime
import urlparse

# Default settings...
DRIVER_VERSION = "1.20"
HARDWARE_NAME = "Atmocom-UDP"
DRIVER_NAME = 'AtmocomUDP'

def loader(config_dict, engine):
    return AtmocomUDPDriver(**config_dict[DRIVER_NAME])

def confeditor_loader():
    return AtmocomUDPConfEditor()

def logmsg(level, msg):
    syslog.syslog(level, 'atmocomudp: %s: %s' %
                  (threading.currentThread().getName(), msg))

def logdbg(msg):
    logmsg(syslog.LOG_DEBUG, msg)

def loginf(msg):
    logmsg(syslog.LOG_INFO, msg)

def logerr(msg):
    logmsg(syslog.LOG_ERR, msg)

class AtmocomUDPConfEditor(weewx.drivers.AbstractConfEditor):
    @property
    def default_stanza(self):
        return """
[AtmocomUDP]
    driver = user.atmocomudp
    udp_address = <broadcast>
    udp_port = 12000
    udp_timeout = 90
    share_socket = True
    station_units = weewx.US
    log_raw_packets = False

    [[sensor_map]]
        outTemp = tempf.WUStationID
        outHumidity = humidity.WUStationID
        inTemp = indoortempf.WUStationID
        inHumidity = indoorhumidity.WUStationID
        pressure = absbaromin.WUStationID
        windDir = winddir.WUStationID
        windSpeed = windspeedmph.WUStationID
        windGust = windgustmph.WUStationID
        UV = UV.WUStationID
        rain = rainindelta.WUStationID
        radiation = solarradiation.WUStationID
"""

    def prompt_for_settings(self):
        settings = dict()
        settings['sensor_map'] = dict()
        print "\nConfiguring AtmocomUDP station settings...\n"
        print "This is the broadcast address that we should be listening"
        print "on for packets.  If the driver throws an error on start,"
        print "try one of the other listed common values (in order)."
        print "This seems to be platform-specific.  All three work on"
        print "Debian Linux and my Raspberry Pi, but only 0.0.0.0 works"
        print "on my Macbook running OS-X or MacOS.  Don't ask about"
        print "Windows, since I don't have a test platform to see"
        print "if it will even work."
        print "\n(Common values: <broadcast> , 0.0.0.0 , 255.255.255.255)"
        #settings['udp_address'] = self._prompt('udp_address', '<broadcast>', ['<broadcast>', '0.0.0.0', '255.255.255.255'])
        settings['udp_address'] = self._prompt('udp_address', '<broadcast>', None)

        print "\nThe IP port that we should be listening for UDP packets"
        print "from.  Atmocom\'s default is 12000.\n"
        settings['udp_port'] = self._prompt('udp_port', '12000', None)

        print "\nThe number of seconds that we should wait for an incoming"
        print "packet on the UDP socket before we give up and log an"
        print "error into syslog.  I cannot determine whether or not"
        print "weewx cares whether a station driver is non-blocking or"
        print "blocking, but encountered a situation in testing the"
        print "WeatherFlow driver that this is based on where the Hub"
        print "rebooted for a firmware update and it caused the driver to"
        print "throw a timeout error and exit.  I have no idea what the"
        print "default timeout value even is, but decided to make it"
        print "configurable in case it is important to someone else.  My"
        print "default of 90 seconds seems reasonable, with most PWS devices"
        print "sending Weather Underground \"rapid fire\" observations every"
        print "15-60 seconds.  If you are an old-school programmer like me"
        print "who thinks that computers should wait forever until they"
        print "receive data, the Python value \"None\" should disable the"
        print "timeout.  In any case, the driver will just log an error"
        print "into syslog and keep on processing.  It isn't like it is"
        print "the end of the world if you pick a wrong value, but you may"
        print "have a better chance of missing packets during the brief"
        print "error trapping time with a really short duration.\n"
        settings['udp_timeout'] = self._prompt('udp_timeout (1-65535, None)', '90', None)

        print "\nWhether or not the UDP socket should be shared with other"
        print "local programs also listening for Atmocom UDP packets.  Default"
        print "is True with some hesitation, because I suspect that some obscure"
        print "Python implementation will have problems sharing the socket.  Feel"
        print "free to set it to False if it creates any problems on your platform.\n"
        settings['share_socket'] = self._prompt('share_socket (True/False)', 'True', ['True', 'False'])

        print "\nEnable writing all raw UDP packets received to syslog,"
        print "or wherever weewx is configured to send log info.  Will"
        print "fill up your logs pretty quickly, so only use it as"
        print "a debugging tool or to identify sensors.\n"
        settings['log_raw_packets'] = self._prompt('log_raw_packets (True/False)', 'False', ['True', 'False'])

        print "\nSpecify what measurement units are being used by the attached station."
        print "Weather Underground apparently *only* accepts input in imperial units,"
        print "but other intercepted services may send metric units.  This setting"
        print "just tells weewx what units you are sending...your sensor_map entries"
        print "(defined later) will need to handle the actual mapping of the URL-encoded"
        print "variable names to weewx database field names."
        print "Set to weewx.US by default, with a footnote that I\'m a US citizen where"
        print "metric is still treated as a dirty word, and apologize to the world for"
        print "WU apparently not having any metric upload options.\n"
        print "References:  http://www.weewx.com/docs/customizing.htm#units"
        print "https://web.archive.org/web/20130430065507/http://wiki.wunderground.com/index.php/PWS_-_Upload_Protocol\n"
        print "weewx.METRICWX = mm+m/s\nweewx.METRIC = cm+km/hr\nweewx.US = in/mph\n"
        settings['station_units'] = self._prompt('station_units (Weather Underground protocol requires weewx.US)', 'weewx.US', ['weewx.US', 'weewx.METRIC', 'weewx.METRICWX'])
        wu_key = raw_input("\nEnter your Weather Underground station ID (or another supported unique identifier being emitted by your station): ")

        print "\nBuilding default sensor_map...\n"

        if settings['station_units'] == 'weewx.US':
            wu_sensors = { 'outTemp': 'tempf', 'outHumidity': 'humidity', 'inTemp': 'indoortempf', 'inHumidity': 'indoorhumidity', 'pressure': 'absbaromin', 'windDir': 'winddir', 'windSpeed': 'windspeedmph', 'windGust': 'windgustmph', 'UV': 'UV', 'rain': 'rainindelta', 'radiation': 'solarradiation' }
        else:
            wu_sensors = { 'outTemp': 'tempc', 'outHumidity': 'humidity', 'inTemp': 'indoortempc', 'inHumidity': 'indoorhumidity', 'pressure': 'absbaromin', 'windDir': 'winddir', 'windSpeed': 'windspeedmps', 'windGust': 'windgustmps', 'UV': 'UV', 'rain': 'rainmmdelta', 'radiation': 'solarradiation' }
            print "\n***** ALERT!  weewx.METRIC and weewx.METRICWX station units will require manually *****"
            print "***** editing the sensor_map after this process completes.  Building a bogus map. *****\n"

        weewx_sensor = ''
        for weewx_sensor in wu_sensors.keys():
            settings['sensor_map'][weewx_sensor] = wu_sensors[weewx_sensor] + "." + wu_key
            print "     " + weewx_sensor + " = " + wu_sensors[weewx_sensor] + "." + wu_key

        print "\nTo make changes to the default sensor_map above for more complex"
        print "scenarios, you will need to manually edit weewx.conf at the path below."
        print "Please see the readme file for details.\n"
        return settings 

class AtmocomUDPDriver(weewx.drivers.AbstractDevice):

    def parseUDPPacket(self,pkt):
        packet = dict()

        obs_type = ''
        if 'updateweatherstation.php' in str(pkt):   # Parse Weather UnderWHO posts
            obs_type="WU"
        if '/endpoint' in str(pkt):   # Parse Ambient Weather posts
            obs_type="Ambient"

        if obs_type in ["WU", "Ambient"]:
            message=''
            try:
                message=eval(str(pkt))[0]
            except SyntaxError:
                logerr('Packet parse error: %s' % pkt)

            # Cheap URL hack to make decode also grab station ID
            message = message.replace("?","&")

            obs=dict(urlparse.parse_qsl(message.decode("utf-8")))

            # Handle utcdate=now packets, from stations without clocks
            if obs['dateutc'].lower() == 'now':
                obs_time = datetime.datetime.utcnow()
            else:
                obs_time = datetime.datetime.strptime(obs['dateutc'],"%Y-%m-%d %H:%M:%S")
            time_epoch = int((obs_time-datetime.datetime(1970,1,1)).total_seconds())

            if obs_type == "WU":
                obs_label = obs['ID']
            if obs_type == "Ambient":
                obs_label = obs['PASSKEY']
            packet['ID'] = obs_label
            packet['time_epoch'] = time_epoch
            obs_keys = obs.keys()
            for i in obs_keys:
                obs_item = i + "." + obs_label
                packet[obs_item] = obs[i]

            # Calculate rain differences, since WU protocol does not include rain since last packet
            for rain_item in self.raintype:
                rain_key = rain_item + "." + obs_label
                if rain_key in packet:
                    delta_key = rain_item + 'delta' + "." + obs_label
                    if rain_key not in self.lastrain:
                        self.lastrain[rain_key] = packet[rain_key]
                        packet[delta_key] = '0.00'
                    else:
                        if float(self.lastrain[rain_key]) > float(packet[rain_key]):
                            # Start over from zero if station value wraps around or resets
                            self.lastrain[rain_key] = packet[rain_key]
                            packet[delta_key] = packet[rain_key]
                        else:
                            packet[delta_key] = str(float(packet[rain_key]) - float(self.lastrain[rain_key]))
                        self.lastrain[rain_key] = packet[rain_key]

            return packet

        else:
            loginf('Corrupt/unknown UDP packet? %s' % str(pkt))
            return False

    def buildMyLoopPacket(self,pkt,sensor_map, station_units):
        packet = dict()
        if 'time_epoch' in pkt:
            packet = {'dateTime': pkt['time_epoch'],
                'usUnits' : station_units}

        for pkt_weewx, pkt_label in sensor_map.iteritems():
            if pkt_label in pkt:
                packet[pkt_weewx] = eval(pkt[pkt_label])

        return packet

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        self._log_raw_packets = tobool(stn_dict.get('log_raw_packets', False))
        self._udp_address = stn_dict.get('udp_address', '<broadcast>')
        self._udp_port = int(stn_dict.get('udp_port', 12000))
        self._udp_timeout = int(stn_dict.get('udp_timeout', 90))
        self._share_socket = tobool(stn_dict.get('share_socket', True))
        self._station_units = eval(stn_dict.get('station_units', 'weewx.METRICWX'))
        self._sensor_map = stn_dict.get('sensor_map', {})
        if not self._sensor_map:
            logerr('*** ERROR!  sensor_map is empty!  Terminating, since it would be silly to continue when we are not receiving data...')
            print "\nERROR!  sensor_map is empty!  Please check your weewx.conf file to ensure that your sensor_map is present and in the correct syntax/spacing."
            print "See the readme file for details on creating a sensor_map."
            print "\nTerminating, since it would be silly to continue when we are not receiving data...\n"
            exit()
        else:
            loginf('sensor map is %s' % self._sensor_map)
            loginf('*** Sensor names per packet type')
        self.raintype = ( 'rainin', 'dailyrainin', 'weeklyrainin', 'monthlyrainin', 'yearlyrainin' )
        self.lastrain = { }
 
    def hardware_name(self):
        return HARDWARE_NAME


    def genLoopPackets(self):
        loginf('Listening for UDP broadcasts to IP address %s on port %s, with timeout %s and share_socket %s...' % (self._udp_address,self._udp_port,self._udp_timeout,self._share_socket))

        s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        if self._share_socket == True:
            s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind((self._udp_address,self._udp_port))
        s.settimeout(self._udp_timeout)

        while True:
            timeouterr=0
            try:
                m=s.recvfrom(1024)
            except timeout:
                timeouterr=1
                logerr('Socket timeout waiting for incoming UDP packet!')
            if timeouterr == 0:
                if self._log_raw_packets:
                    loginf('raw packet: %s' % m)
                m3=''
                m2=self.parseUDPPacket(m)
                if m2:
                    m3=self.buildMyLoopPacket(m2, self._sensor_map, self._station_units)
                if len(m3) > 2:
                    yield m3


