#!/usr/bin/python

import sys
import traceback
import json
import logging
import httplib2
http = httplib2.Http()

BASE_URL = 'https://api2.dynect.net'

class Dynect:
	"""
	Class member variables
	"""
	_token = ""
	_loginJson = ""
	_logging = None
	_std_out = 2 
	
	"""
	Constructor
	
	customername/username/password: the login credentials
	"""
	def __init__(self, customername, username, password):
		self._log_debug("Dynect:__init__: Enter")
		self._create_session(customername, username, password)
		
	"""
	Destructor
	"""
	def __del__(self):
		self._log_debug("Dynect:__del__: Enter")
		self._destroy_session()
		self._loginJson = ""

	"""
	create_session - Does the login to create the token
	
	customername/username/password: the login credentials
	
	returns: True if success
	"""
	def _create_session(self, customername, username, password):
		try:
			self._log_debug("Dynect:_create_session: Enter")
			# lets create the json to log in and store in case of a timneout
			params = {}
			params["customer_name"] = customername
			params["user_name"] = username
			params["password"] = password
			self._loginJson = json.JSONEncoder().encode(params)
			
			# now make the call to our rest helper function to log the user in
			result = self._do_rest_call('/REST/Session/', 'POST', self._loginJson)
			if result["status"] == "success":
				self._token = result["data"]["token"]
				self._log_debug("Dynect:_create_session: Success")
				return True
			else:
				self._log_error("Dynect:_create_session: Failed")
				return False
		except:
			self._log_error("Dynect:_create_session: Error! - " + self._format_excpt_info())
			return False


			
	"""
	destroy_session - logs out and removes token
	
	"""
	def _destroy_session(self):
		try:
			self._log_debug("Dynect:_destroy_session: Enter")
			result = self._do_rest_call('/REST/Session/', 'DELETE',  '')
			self._token = ''
		except:
			self._log_error("Dynect:_destroy_session: Error! - " + self._format_excpt_info())
		
	"""
	add_a_record - Does the login to create the token
	
	zone, fqdn, ip_address, ttl of the A record to be added
	
	returns: True if success
	"""
	def add_a_record(self, zone, fqdn, ip_address, ttl=0):
		try:
			self._log_debug("Dynect:add_a_record: Enter")
			self._log_debug("Dynect:add_a_record: adding - zone:" + zone + ", fqdn:" + fqdn + ", ip:" + ip_address + ", ttl:" + ttl)
			# lets create the A record Json
			params = {}
			params["rdata"] = {}
			params["rdata"]["address"] = ip_address
			params["ttl"] = ttl
			
			# now make the call to our rest helper function to a
			result = self._do_rest_call('/REST/ARecord/' + zone + '/' + fqdn +  '/', 'POST', json.JSONEncoder().encode(params))
			if result["status"] == "success":
				# if we succeeded attempt to publish this zone
				publish_result = self.publish_zone(zone)
				if publish_result == True:
					self._log_info("Dynect:add_a_record: A record added")
					self._log_debug("Dynect:add_a_record: Exit - return True")
					return True
				else:
					self._log_warning("Dynect:add_a_record: A record failed to publish add")
					self._log_debug("Dynect:add_a_record: Exit - return False")
					return False
			else:
				
				self._log_warning("Dynect:add_a_record: A record failed to add")
				self._log_debug("Dynect:add_a_record: Exit - return False")
				return False
		except:
			self._log_error("Dynect:_destroy_session: Error! - " + self._format_excpt_info())
			return False
			
	"""
	delete_a_record - Does the login to create the token
	
	zone, fqdn, ip_address, ttl of the A record to be added
	
	returns: True if success
	"""
	def delete_a_record(self, zone, fqdn, ip_address):
		try:
			self._log_debug("Dynect:delete_a_record: Enter")
			self._log_debug("Dynect:delete_a_record: deleteing - zone:" + zone + ", fqdn:" + fqdn + ", ip:" + ip_address)
			#first we need to get the a record
			#outId = self.get_a_record_for_fqdn(zone, fqdn, ip_address)
			outId, out_fqdn = self.search_for_a_record_in_zone(zone, fqdn, ip_address)
			
			if outId == "":				
				self._log_warning("Dynect:delete_a_record: Unable to find A record to delete")
				self._log_debug("Dynect:delete_a_record: Exit - return False")
				return False
				
			# now make the call to our rest helper function to delete
			result = self._do_rest_call('/REST/ARecord/' + zone + '/' + out_fqdn +  '/' + outId + '/', 'DELETE', '')
			if result["status"] == "success":
				# if we succeeded attempt to publish this zone
				publish_result = self.publish_zone(zone)
				if publish_result == True:
					self._log_info("Dynect:delete_a_record: A record deleted")
					self._log_debug("Dynect:delete_a_record: Exit - return True")
					return True
				else:
					self._log_warning("Dynect:delete_a_record: A record failed to publish delete")
					self._log_debug("Dynect:delete_a_record: Exit - return False")
					return False
			else:
				self._log_warning("Dynect:delete_a_record: A record failed to delete")
				self._log_debug("Dynect:delete_a_record: Exit - return False")
				return False
		except:
			self._log_error("Dynect:delete_a_record: Error! - " + self._format_excpt_info())
			raise
			return False
	
	"""
	get_a_record_for_fqdn - Gets the record id of the ip address for the fqdn
	
	zone, fqdn, ip_address of the A record id to return
	
	returns: record id or empty if fails
	"""
	def get_a_record_for_fqdn(self, zone, fqdn, ip_address):
		try:
			self._log_debug("Dynect:get_a_record_for_fqdn: Enter")
			recordsArray = self.get_a_records_for_fqdn(zone, fqdn)
			for record in recordsArray:				
				result = self._do_rest_call(record, 'GET', '')
				self._log_debug("Dynect:get_a_record_for_fqdn: returned record")
				if result["data"]["rdata"]["address"] == ip_address:
					self._log_debug("Dynect:get_a_record_for_fqdn: Exit - found ip, record")
					return str(result["data"]["record_id"])
			self._log_warning("Dynect:get_a_record_for_fqdn: No record matched " + ip_address + " at " + fqdn)
			self._log_debug("Dynect:get_a_record_for_fqdn: Exit - return empty")
			return ""
		except:
			self._log_error("Dynect:get_a_record_for_fqdn: Error! - " +self._format_excpt_info())
			return ""
	
	
	"""
	get_a_records_for_fqdn - Get all of the A records for a given fqdn
	
	zone, fqdn, A records to return
	
	returns: A records
	"""
	def get_a_records_for_fqdn(self, zone, fqdn):
		try:
			self._log_debug("Dynect:get_a_records_for_fqdn: Enter")
			self._log_debug("Dynect:get_a_records_for_fqdn: /REST/ARecord/" + zone + "/" + fqdn +  "/")
			
			# now make the call to our rest helper function to  get the records
			result = self._do_rest_call('/REST/ARecord/' + zone + '/' + fqdn +  '/', 'GET', '')
			if result["status"] == "success":
				self._log_debug("Dynect:get_a_records_for_fqdn: Exit - return result")
				return result["data"]
			else:
				self._log_warning("Dynect:get_a_records_for_fqdn: Failed to get A record Array")
				self._log_debug("Dynect:get_a_records_for_fqdn: Exit - return empty")
				return ""
		except:
			self._log_error("Dynect:get_a_records_for_fqdn: Error! - " + self._format_excpt_info())
			return ""

	"""
	search_for_a_record_in_zone - Finds an a record in the fqdn or any fqdn's beneatht the provided one. If passed "" the whole zone will be searched
	
	zone, ip_address of record
	
	returns: record id
	"""
	def search_for_a_record_in_zone(self, zone, fqdn, ip_address):
		try:
			self._log_debug("Dynect:search_for_a_record_in_zone: Enter")
			self._log_debug("Dynect:search_for_a_record_in_zone: zone - " + zone + "    fqdn - " + fqdn)
			
			if fqdn == "":
				# now make the call to our rest helper function to  get the NodeList
				result = self._do_rest_call('/REST/NodeList/' + zone + '/', 'GET', '')
				print result
				if result["status"] == "success":
					for fqdns in result["data"]:
						recordId = self.get_a_record_for_fqdn(zone, fqdns, ip_address)
						if recordId != "":
							self._log_debug("Dynect:search_for_a_record_in_zone: found record! Id is: " + recordId)
							return recordId, fqdns
				else:
					self._log_warning("Dynect:search_for_a_record_in_zone: Failed to get record, may not be any")
					self._log_debug("Dynect:search_for_a_record_in_zone: Exit - return empty")
					return "", ""
				return "", ""
			else:
				# now make the call to our rest helper function to  get the NodeList
				result = self._do_rest_call('/REST/NodeList/' + zone + '/' + fqdn + '/', 'GET', '')
				print result
				if result["status"] == "success":
					for fqdns in result["data"]:
						recordId = self.get_a_record_for_fqdn(zone, fqdns, ip_address)
						if recordId != "":
							self._log_debug("Dynect:search_for_a_record_in_zone: found record! Id is: " + recordId)
							return recordId, fqdns
				else:
					self._log_warning("Dynect:search_for_a_record_in_zone: Failed to get record, may not be any")
					self._log_debug("Dynect:search_for_a_record_in_zone: Exit - return empty")
					return "", ""
				return "", ""
		except:
			self._log_error("Dynect:get_a_records_for_fqdn: Error! - " + self._format_excpt_info())
			return "", ""


	"""
	delete_a_record - Does the login to create the token
	
	zone, fqdn, ip_address, ttl of the A record to be added
	
	returns: True if success
	"""
	def publish_zone(self, zone):
		try:
			self._log_debug("Dynect:publish_zone: Enter")
			# lets create the A record Json
			params = {}
			params["publish"] = 1
			
			# now make the call to our rest helper function to a
			result = self._do_rest_call('/REST/Zone/' + zone + '/', 'PUT', json.JSONEncoder().encode(params))
			if result["status"] == "success":
				self._log_debug("Dynect:publish_zone: Exit - return True")
				return True
			else:
				self._log_warning("Dynect:publish_zone: Failed to publish zone")
				self._log_debug("Dynect:publish_zone: Exit - return False")
				return False
		except:
			self._log_error("Dynect:publish_zone: Error! - " + self._format_excpt_info())
			return False
	
	"""
	do_rest_call - utility function to take some repition out of the http requests
	
	apiname: the /REST/... function to cal
	verb: either PUT, POST, GET or DELETE
	inputJson: the parameters to pass in a string of json or an empty string if no parameters
	
	returns: array built from json content of return
	"""
	def _do_rest_call(self,  apiname, verb,  inputJson):
		try:
			self._log_debug("Dynect:_do_rest_call: Enter")
			response = ""
			content = ""
			http.force_exception_to_status_code = True
			if self._token == "":
				response, content = http.request(BASE_URL + apiname,  verb , inputJson, headers={'Content-type': 'application/json'})
			else:
				response, content = http.request(BASE_URL + apiname, verb, inputJson, headers={'Content-type': 'application/json', 'Auth-Token':  self._token})
			result = json.loads(content)
			self._log_debug("Dynect:_do_rest_call: Exit")
			return result
		except:
			self._log_error("Dynect:_do_rest_call: Error! - " + self._format_excpt_info())
			return ""
			
	'''
	_format_except_inf - return a readable exception
	
	** code for this function basically from the Linix Journal: http://www.linuxjournal.com/node/5821/print
	'''
	def _format_excpt_info(maxTBlevel=5):
		cla, exc, trbk = sys.exc_info()
		excName = cla.__name__
		try:
			excArgs = exc.__dict__["args"]
		except KeyError:
			excArgs = "<no args>"
		excTb = traceback.format_tb(trbk, maxTBlevel)
		return excName # + excArgs + excTb
	
	'''
	Set of functions to handle logging, by passing in the logging object we can let the calling program decide
	if it wants to log, how it wants to log and let it use it's own logging agent
	'''
	
	'''
	use_logger - the main call to determine logging
	
	logger: the logging object, passed in if you want to use it else None
	stdout: int for printing to the console, 0 - critical ... 4 - Debug
	'''
	def use_logger(self, logger, stdout):
		try:
			self._logging = logger
			self._std_out = stdout
		except:
			pass
		
	def _log_debug(self, msg):
		try:
			if self._std_out > 4:
				print msg
			if self._logging == None:
				return
			self._logging.debug(msg)
		except:
			pass
		
	def _log_info(self, msg):
		try:
			if self._std_out > 3:
				print msg
			if self._logging == None:
				return
			self._logging.info(msg)
		except:
			pass
		
	def _log_warning(self, msg):
		try:
			if self._std_out > 2:
				print msg
			if self._logging == None:
				return
			self._logging.warning(msg)
		except:
			pass
		
	def _log_error(self, msg):
		try:
			if self._std_out > 1:
				print msg
			if self._logging == None:
				return
			self._logging.error(msg)
		except:
			pass
		
	def _log_critical(self, msg):
		try:
			if self._std_out > 0:
				print msg
			if self._logging == None:
				return
			self._logging.critical(msg)
		except:
			pass

