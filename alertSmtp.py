#!/usr/bin/env python

import dynect
from dynect import  *

from os import fork, chdir, setsid, umask
from sys import exit
import ConfigParser
import re
import smtpd
import asyncore
import xml.dom.minidom
import logging
import logging.handlers
import socket

config = ConfigParser.ConfigParser()

class AlertResponderSMTPServer(smtpd.SMTPServer):
	"""
	An smtp server specifically to listen for and reply to alert emails
	"""
	fqdn = ""
	zone = ""
	ttl = ""
	cn = ""
	un = ""
	pwd = ""
	host = ""
	action_level = ""
	log_file = ""
	log_byte_size = 0
	logger = None
	failover_address = ""
	# logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL
	log_level = logging.INFO
	def __init__(self):
		config.readfp(open('/etc/gomez_alerts/dynect.cfg'))
		
		self.cn = config.get('credentials', 'cn')
		self.un = config.get('credentials', 'un')
		self.pwd = config.get('credentials', 'pwd')
		
		self.ttl = config.get('dns_settings', 'ttl')
		self.zone = config.get('dns_settings', 'zone')
		self.fqdn = config.get('dns_settings', 'fqdn')
		self.host = config.get('smtp_settings', 'host')
		self.action_level = config.get('gomez_alert_settings', 'action_level')
		
		self.log_file = config.get('logging', 'log_file')
		string_size = config.get('logging', 'log_byte_size')
		llevel = config.get('logging', 'log_level')
		
		self.log_byte_size = int(string_size)
		
		if llevel == "DEBUG":
			self.log_level = logging.DEBUG
		elif llevel == "INFO":
			self.log_level = logging.INFO
		elif llevel == "WARNING":
			self.log_level = logging.WARNING
		elif llevel == "ERROR":
			self.log_level = logging.ERROR
		else:
			self.log_level = logging.CRITICAL
		
		#set the logging leve
		self.logger = logging.getLogger('alertSmtpLogger')
		self.logger.setLevel(self.log_level)

		# Add the log message handler to the logger
		handler = logging.handlers.RotatingFileHandler(self.log_file, maxBytes=self.log_byte_size, backupCount=5)

		self.logger.addHandler(handler)
		
		self.logger.info("Alert responding smtp sever running on port 25")
		
		smtpd.SMTPServer.__init__(self, (self.host, 25), None)

	def process_message(self, peer, mailfrom, rcpttos, data):
		self.logger.debug("Entering process_message")
		self.logger.debug("email from peer: (" + str(peer[0]) + "," + str(peer[1]) + ")")
		self.logger.debug("email from: " +  mailfrom)

		config.readfp(open('/etc/gomez_alerts/dynect.cfg'))
                self.failover_address = config.get('dns_settings', 'failover_address')
		
		# Do your authentication of email test here
                if  True:
			original_ip = ""
			try:
				original_ip = socket.gethostbyname(self.fqdn)
			except:
				self.logger.warning("Could not get ip for " + self.fqdn)
				return
                        if original_ip  != self.failover_address:
				self.logger.info("Received email from gomez alerting")
        	                xmlOut = re.findall('<GPN_MESSAGE.*</GPN_MESSAGE>',  data)
	
        	                self.logger.debug("Xml received is" + xmlOut[0])
	
        	                # first get the xml into dom format to deal with from string
                	        dom = xml.dom.minidom.parseString(xmlOut[0])
                       	 	# lets grab the alert out 
	                        alert = dom.getElementsByTagName("alert")
        	                #now lets get the id and status
                	        idXml = alert[0].getElementsByTagName("alertId")[0]
                        	alertId = self.getTextFromXml(idXml.childNodes)
	                        statusXml = alert[0].getElementsByTagName("status")[0]
        	                status = self.getTextFromXml(statusXml.childNodes)
				
				self.logger.debug("alert id is" + alertId)
				self.logger.debug("status is" + status)
	
				#make sure we are looking at the status level that we care about
				if status == self.action_level or status == "SEVERE":
					self.logger.info("Alert Found, Connecting to Dynect to remove IP from records")
				
					# connect to dynect
					dyn = Dynect(self.cn, self.un, self.pwd)
					dyn.use_logger(self.logger, 5)	
					self.logger.info("Successfully connected!")
					dyn.add_a_record(self.zone, self.fqdn, self.failover_address, self.ttl)
					# now pull out all the sites from the xml that we need to switch
					sites = dom.getElementsByTagName("site")
					dyn.delete_a_record(self.zone, self.fqdn, original_ip)
		else:
			self.logger.info("Received mail from " + mailfrom + "... ignoring")
			

			
	def getTextFromXml(self, nodelist):
		rc = []
		for node in nodelist:
			if node.nodeType == node.TEXT_NODE:
				rc.append(node.data)
		return ''.join(rc)

def main():
        smtp_server = AlertResponderSMTPServer()
        try:
                asyncore.loop()
        except KeyboardInterrupt:
                smtp_server.close()

# Dual fork hack to make process run as a daemon
if __name__ == "__main__":
        try:
                pid = fork()
                if pid > 0:
                        exit(0)
        except OSError, e:
                exit(1)

        chdir("/")
        setsid()
        umask(0)

        try:
                pid = fork()
                if pid > 0:
                        exit(0)
        except OSError, e:
                exit(1)

        main()
