#coding=utf-8

import socket

## ------------------------------------
PROTOCOL_ID = 0 # constant, don't change
trans_id = 0 # trans_id, plus 1 for each packet
## ------------ PARAMETERS ------------
max_modbus_data_len = 1081
max_block_len = 1020
## ------------ USERDEFINE ------------
USERNAME = b'DEFAULT NAME' # username defined by user
UNIT_ID = 1 # defined by user
tcpsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# pack the modbus frame with the modbus header
# trans_id 2bytes, Protocol ID = 0x00, length 2bytes, Unit ID 1byte
def makeframe(packdata):
	payload = b''
	# trans id: 2 bytes
	payload += int.to_bytes(trans_id, 2, 'big')
	# protocol id: 2 bytes, normally 0
	payload += int.to_bytes(PROTOCOL_ID, 2, 'big')
	# length: 2 bytes
	if (len(packdata) + 2) > 0xFFFF:
		payload += b'\xFF\xFF'
	else:
		payload += int.to_bytes((len(packdata) + 2), 2, 'big')
	# unit id: 1 byte
	payload += int.to_bytes(UNIT_ID, 1, 'big')
	# Modbus Function Code/FCode: 1 byte, always '\x5a' in UMAS protocol
	payload += b'\x5A'
	payload += packdata
	return payload


# send the tcp frame, and increase the counter
def sendframe(payload):
	global trans_id
	tcpsock.send(payload)
	trans_id += 1
	trans_id = trans_id & 0xFFFF
	r = tcpsock.recv(2048) #
	return r

def connectionInit():
	max_modbus_data_len = 1081
	max_block_len = 1020
	sessionkey = '\x00'
	
	payload = b'\x00\x02' # read ID
	sendframe(makeframe(payload))
	payload = b'\x00\x01\x00' # initialize a connection
	response = sendframe(makeframe(payload))
	# get PLC information
	if response[9] == 0xfe:
		max_modbus_data_len = ((response[0xb] << 8) ^ response[0xa]) + 1 # comment it will be OK
		max_block_len = max_modbus_data_len - 0x3d # comment it will be OK
		pass
	else:
		print('ERROR: connection initialize failed')
		exit(1)
	payload = b'\x00\x0a\x00' + b'T'*0xf9 # ping
	sendframe(makeframe(payload))
	payload = b'\x00\x03\x00' # read project info, subcode 0x00
	sendframe(makeframe(payload))
	payload = b'\x00\x03\x04' # read project info, subcode 0x04
	sendframe(makeframe(payload))
	payload = b'\x00\x04' # read PLC status
	sendframe(makeframe(payload))
	payload = b'\x00\x01\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x0a\x00' + bytes(list(range(0, 0xf9+1)))
	sendframe(makeframe(payload))
	payload = b'\x00\x04'
	sendframe(makeframe(payload))
	payload = b'\x00\x04'
	sendframe(makeframe(payload))
	## UMAS FCode 0x20: READ MEMORY BLOCK
	## 
	payload = b'\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x00\x00\x00\x00\x64\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x5a\x01\x00\x00\xf6\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x5a\x02\x00\x00\xf6\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x46\x03\x00\x00\xf6\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x3c\x04\x00\x00\xf6\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x32\x05\x00\x00\xf6\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x14\x00\x28\x06\x00\x00\x0c\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x13\x00\x00\x00\x00\x00\x64\x00'
	sendframe(makeframe(payload))
	payload = b'\x00\x20\x00\x13\x00\x64\x00\x00\x00\x9c\x00'
	sendframe(makeframe(payload))
	## UMAS FCode 0x10: TAKE PLC RESERVATION
	payload = b'\x00\x10\x43\x4c\x00' + int.to_bytes(len(USERNAME) & 0xFFFF, 2, 'big') + USERNAME
	response = sendframe(makeframe(payload))
	## response of FCode 0x10: tell the result, if success, return the sessionkey(important)
	if response[9] == 0xfe:
		print('get PLC reservation successfully')
		sessionkey = chr(response[0xa])
		#print('session key = %d' % ord(sessionkey))
		key = sessionkey.encode('latin1')
	else:
		print('ERROR: PLC is reserved, cannot get reservation')
		key = b'\x00'
	payload = key + b'\x04'
	sendframe(makeframe(payload))
	payload = key + b'\x50\x15\x00\x01\x0b'
	sendframe(makeframe(payload))
	payload = key + b'\x50\x15\x00\x01\x07'
	sendframe(makeframe(payload))
	payload = key + b'\x12'
	sendframe(makeframe(payload))
	payload = key + b'\x04'
	sendframe(makeframe(payload))
	payload = b'\x00\x02'
	sendframe(makeframe(payload))
	payload = b'\x00\x58\x01\x00\x00\x00\x00\xff\xff\x00\x70'
	sendframe(makeframe(payload))
	payload = b'\x00\x58\x07\x01\x80\x00\x00\x00\x00\xfb\x00'
	sendframe(makeframe(payload))
	payload = key + b'\x04'
	sendframe(makeframe(payload))
	payload = b'\x00\x58\x07\x01\x80\x00\x00\x00\x00\xfb\x00'
	sendframe(makeframe(payload))
	return (sessionkey, max_modbus_data_len, max_block_len)

def modiconInit(host, port):
	tcpsock.connect((host,port))
	sessionkey, max_modbus_data_len, max_block_len = connectionInit()
	print('connected')
	#tcpsock.close()
	return (sessionkey, max_modbus_data_len, max_block_len)

def socket_reopen():
	global tcpsock
	tcpsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

def setdefaulttimeout(s):
	socket.setdefaulttimeout(s)
	print(type(s))
