#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  :platform: Linux, Windows
  :synopsis: all operation of adapter between MCTP-over-TCP/IP to MCTP-over-SMBus

  OPENSPDM: MCTP-over-TCP/IP
  --------------------------

  .. tabularcolumns:: |l|m|l|

  +------------------+----------------+-------------------------------------+
  | OPENSPDM item    | Length (bytes) | Value and Description               |
  +==================+================+=====================================+
  | Transmit command | 4              | Start: 0x0000DEAD                   |
  |                  |                | Stop:  0x0000FFFE                   |
  |                  |                | Data:  0x00000001                   |
  +------------------+----------------+-------------------------------------+
  | Transport Type   | 4              | 0x00000001                          |
  +------------------+----------------+-------------------------------------+
  | Buffer Size      | 4              | size of payload in bytes            |
  +------------------+----------------+-------------------------------------+
  | Data Bytes       | L (variable)   | MCTP packet as shown in below figure|
  +------------------+----------------+-------------------------------------+

  .. figure:: mctp_type5_spdm.jpg
     :scale: 80 %
     :alt: mctp packet with SPDM payload

     MCTP packet for SPDM


  CPLD: MCTP over SMBus
  ----------------------

  .. figure:: mctp-over-smbus.jpg
     :scale: 80 %
     :alt: mctp packet over smbus

     MCTP over SMBus


  Example::

     GET_VERSION:
     CPLD:      0F 0A 01 00 00 00 C8 05 10 84 00 00 B0
     OPENSPDM:  00 00 00 01 00 00 00 01 00 00 00 05 05 10 84 00 00

"""
from __future__ import print_function
from __future__ import division

import logging
import os, struct
from crccheck.crc import Crc8Smbus

from collections import OrderedDict
from array import array
import random

logger = logging.getLogger(__name__)

socket_data_hdr=array('B',[0,0,0,1,0,0,0,1])

transmit_cmd  = [b'\x00\x00\x00\x01', b'\x00\x00\xde\xad', b'\x00\x00\xff\xfe']
transportType = b'\x00\x00\x00\x01'
transmit_head = [i+transportType for i in transmit_cmd]

def extract_mctp_data(raw_data):
  print(raw_data)
  if raw_data[:8] == socket_data_hdr.tobytes():
    mctp_data = raw_data[8:]
    return mctp_data
  else:
    return False

lst_TransmitCmd   = [b'\x00\x00\x00\x01', b'\x00\x00\xde\xad', b'\x00\x00\xff\xfe']
lst_TransportType = [b'\x00\x00\x00\x01']

def log_list(log_handle, input_data, item_perline):
  """ log long list as multiple lines

  :param log_handle: handle of log file
  :param input_data: input data
  :param item_perline: item number per line

  """
  addr = 0
  msg = '  0x{:03x}: '.format(addr)
  for i in input_data:
    msg += '{:02x} '.format(i)
    addr += 1
    if addr%item_perline == 0:
      log_handle.info('{}'.format(msg))
      msg = '  0x{:03x}: '.format(addr)
  log_handle.info('{}'.format(msg))


def split_multi_random(payload_size):
  """ Split a payload size as multiple random number

  :param payload_size: payload size in bytes
  :return: lst of random bytes

  """
  lst = []
  cnt = payload_size
  while (cnt > 0xf9):
    seg_size = int(128+random.random()*121)  # 122 = 128-6, payload size is limited as 250
    lst.append(seg_size)
    cnt = cnt - seg_size
  lst.append(cnt)
  lst.sort(reverse=True)  # sort a list with desacent order from value high to low
  return lst


class MCTP_SOCKET(object):
  """ class for MCTP over TCP/IP from openspdm

  openspdm traffic is MCTP over socket format

  :param input_data: input data in bytes format

  """
  def __init__(self, input_data):
    self.logger = logging.getLogger(__name__)
    self.data = input_data
    self.transmit_cmd    = self.data[0:4]
    self.transport_type  = self.data[4:8]
    self.trx_buffer_size = self.data[8:12]
    self.data_buffer     = self.data[12:]
    self.spdm_msgcode    = None
    self.spdm_msgstr     = None

  def is_spdm(self):
    """ check if it is SPDM packet  """
    lst_key = list(dict_SPDM_Code.keys())
    if (self.transmit_cmd in lst_TransmitCmd) \
       and (self.transport_type in lst_TransportType) \
       and (self.data_buffer[:2] == b'\x05\x10') \
       and ('0x{:02X}'.format(self.data_buffer[2]) in lst_key):
      self.spdm_msgcode = '0x{:02X}'.format(self.data_buffer[2])
      self.spdm_msgstr = dict_SPDM_Code[self.spdm_msgcode]
      return True
    else: return False


  def is_hello(self):
    """ check if it is openspdm Hello packet """
    if (self.transmit_cmd in lst_TransmitCmd) \
       and (self.transport_type in lst_TransportType) \
       and (b'Hello!' in self.data_buffer):
      return True
    else: return False


  def is_end(self):
    """ check if it is end packet

    """
    if (self.transmit_cmd in lst_TransmitCmd) \
       and (self.transport_type in lst_TransportType) \
       and (self.trx_buffer_size == b'\x00\x00\x00\x00'):
      return True
    else: return False


  def check_pkt(self):
    """ return True if it is a packet """
    return self.is_spdm() or self.is_hello() or self.is_end()


  def get_spdm_data(self):
    """ get SPDM data

     if it is spdm packet, return spdm data
     oterwise, return None.

    """
    if self.is_spdm():
      self.spdm_data = self.data_buffer[1:]
      return self.spdm_data
    else:
      return None

  def get_smbus_data(self):
    """ get data bytes send to smbus

    This is adpter of generation MCTP over smbus data

    """
    self.get_spdm_data()
    cpld_addr = 0x70
    src_addr  = 0x05
    spdm_payload_size = len(self.spdm_data)  # Byte Count = spdm_payload_size + 6
    if spdm_payload_size <= (0xff-6):  # single transaction
      logger.info('spdm_payload_size = {}'.format(spdm_payload_size))
      temp1 = [(src_addr << 1 | 1), 0x00, 0x00, 0x00, 0xc8, 0x05]
      temp2 = array('B', temp1).tobytes() +self.spdm_data
      byte_cnt = len(temp2)
      temp = bytes([cpld_addr << 1|0, 0x0F, byte_cnt]) + temp2
      pec= Crc8Smbus.calc(temp)
      self.smbus_data = bytes([0x0F, byte_cnt]) + temp2 + bytes([pec])
      logger.info("-- Aardvark send out data: {}".format(self.smbus_data))
      #print('-- data bytes send out from Aardvark:', self.smbus_data)
      return self.smbus_data
    else:
      # data is more than 256 bytes, need send on segments with SOM/EOM setting in MCTP header
      # return a list of data here, split large payload as a few small ones (<=0xff) in random size
      lst = split_multi_random(spdm_payload_size)
      # message of MCTP header. Byte 4 of MCTP header
      st_header = [(src_addr << 1 | 1), 0x00, 0x00, 0x00, 0x88, 0x05]  # Bit-7:SOM = 1, Bit-6:EOM = 0  Bit[5:4]- PktSeq# (0-3)
      md_header = [(src_addr << 1 | 1), 0x00, 0x00, 0x00, 0x18, 0x05]  # Bit-7:SOM = 0, Bit-6:EOM = 0  Bit[5:4]- PktSeq# (0-3)
      ed_header = [(src_addr << 1 | 1), 0x00, 0x00, 0x00, 0x58, 0x05]  # Bit-7:SOM = 0, Bit-6:EOM = 1  Bit[5:4]- PktSeq# (0-3)
      self.smbus_data = []
      st_cnt, ed_cnt = lst.pop(0), lst.pop(-1)
      st_bytes = bytes(st_header) + self.spdm_data[:st_cnt]
      st_bytecnt = len(st_bytes)
      st_smbdata = bytes([cpld_addr << 1|0, 0x0F, st_bytecnt]) + st_bytes
      st_pec = Crc8Smbus.calc(st_smbdata)
      st_smbus_data = bytes([0x0f, st_bytecnt]) + st_bytes + bytes([st_pec])
      self.smbus_data.append(st_smbus_data)

      # process middle segments of data in left over lst list
      st_index = st_cnt
      pktseq = 1
      if len(lst) == 0:
        ed_header = [(src_addr << 1 | 1), 0x00, 0x00, 0x00, 0x58, 0x05]  # Bit[7:6]=01b, Bit[5:4] = 01b, two segments, pktseq = 1
      else:
        self.logger.info("-- lst = {}".format(lst))
        # more than two pkts, PktSeq is modulo of 4, value (0, 1, 2, 3)
        for i in lst:
          md_bytes = bytes(md_header) + self.spdm_data[st_index:st_index+i]
          md_bytecnt = len(md_bytes)
          md_smbdata = bytes([cpld_addr << 1|0, 0x0F, md_bytecnt]) + md_bytes
          md_pec = Crc8Smbus.calc(md_smbdata)
          md_smbus_data = bytes([0x0f, md_bytecnt]) + md_bytes + bytes([md_pec])
          self.smbus_data.append(md_smbus_data)
          st_index = st_index + i

      total=len(self.spdm_data)
      ed_bytes = bytes(ed_header) + self.spdm_data[total-ed_cnt:total]  # [-ed_cnt:] -- get last ed_cnt bytes
      ed_bytecnt = len(ed_bytes)
      #self.logger.info("-- ed_bytecnt = {}".format(ed_bytecnt))
      ed_smbdata = bytes([cpld_addr << 1|0, 0x0F, ed_bytecnt]) + ed_bytes
      ed_pec = Crc8Smbus.calc(ed_smbdata)
      ed_smbus_data = bytes([0x0f, ed_bytecnt]) + ed_bytes + bytes([ed_pec])
      self.smbus_data.append(ed_smbus_data)
      # return a list of bytes array in multiple segments of MCTP packets
      if len(lst) == 0:
        self.logger.info("-- send in {} MTP packets: pkt-0 {} -- pkt1 {}".format(len(self.smbus_data), st_cnt, ed_cnt))
      else:
        self.logger.info("-- send in {} MTP packets: {}-{}-{}".format(len(self.smbus_data), st_cnt, lst, ed_cnt))
      return self.smbus_data


  def show_spdm_msg(self):
    """ show SPDM message

    """
    mctp_type, ver = self.data_buffer[0], self.data_buffer[1]
    if (mctp_type, ver) == (0x05, 0x10):
      hexcode   = "0x{:02X}".format(self.data_buffer[2])
      self.logger.info(" -- MCTP Type {:02x} SPDM MSG:({:02X}, {:02X}, {})".format(self.data_buffer[0], \
                     self.data_buffer[1], self.data_buffer[2], dict_SPDM_Code[hexcode]))

  def show(self):
    """ display MCTP_SOCKET data

    """
    self.logger.info("   Transmit Command: {}".format(' '.join(['{:02x}'.format(x) for x in self.transmit_cmd])))
    self.logger.info("Transmit_TranspType: {}".format(' '.join(['{:02x}'.format(x) for x in self.transport_type])))
    self.logger.info("Transmit_BufferSize: {}".format(' '.join(['{:02x}'.format(x) for x in self.trx_buffer_size])))

    if len(self.data_buffer) == 0: return   # do nothing is empty
    self.show_spdm_msg()
    self.logger.info('  -- Data Buffer: ')
    log_list(self.logger, self.data_buffer, 32)
    if b'Hello!' in self.data_buffer:
      self.logger.info(self.data_buffer)


class MCTP_CPLD(object):
  """ MCTP CPLD data

  :param input_data : input data in bytearray format

  """
  def __init__(self, input_data):
    self.logger = logging.getLogger(__name__)
    self.input_data = input_data
    # receive GET_VERSION: 0F 0A 01 00 00 00 C8 05 10 84 00 00 B0
    self.length =len(self.input_data)
    self.pec = self.input_data[-1]
    self.data_buffer = self.input_data[7:self.length-1]
    self.spdm_code = self.data_buffer[2]


  def get_openspdm_data(self):
    """
      openspdm adapter for generation of openspdm data for openspdm communication

    """
    #transmit_cmd   = b'\x00\x00\x00\x01'
    #transport_type = b'\x00\x00\x00\x01'
    # add workaround for VERSION message only support 0x10
    #if self.spdm_code == 0x04:
      # 0F 10 01 00 00 00 C0 05 10 04 00 00 00 02 00 10 00 11 06
      # --> #openspdm: 05 10 04 00 00 00 01 00 10
      #self.input_data[13] = 0x01
      #self.length = self.length - 2

    # add w/a for ALG (0x63) {BaseAsymSel} and {BaseHashSel} no more than one bit
    #if self.spdm_code == 0x63:

      # ALG:     05 10 63 00 00 24 00 01 00 06 00 00 00 90 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      # gd-ALG:  05 10 63 00 00 24 00 01 00 04 00 00 00 80 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    #  self.input_data[16] = 0x04
    #  self.input_data[20] = 0x80
    #  self.input_data[24] = 0x02

    # add w/a for DIGEST (0x01) param2 = 0x01
    #if self.spdm_code == 0x01:
      #****CPLD: data_recv (in hex) = 0f 3a 01 00 00 00 c0
      #          05 10 01 00 97 46 58 c1 30 0c 3c 69 3b f4 ad 27 22 f7 7b e7 95 ba 44 06 2b 72 ac cb 13
      #          06 21 04 0c 48 5f 9d 74 e3 25 46 3d 3a 04 55 f6 45 b1 fd 50 85 fb 52 00 6a
    #  for i in range(59, 10, -1):
    #    self.input_data[i] = self.input_data[i-1]
    #  self.input_data[11] = 0x01

    mctp_data = self.input_data[7:(self.length-1)]
    buffer_size = struct.pack('>I', len(mctp_data))
    self.openspdm_data = b'\x00\x00\x00\x01'*2 + buffer_size + mctp_data
    temp = ' '.join(["%02x"%i for i in self.openspdm_data])
    logger.info('-- send to openspdm_data = {}'.format(temp))

    # NEGOTIATE_ALGORITHM (0xe3), w/a with length 2 bytes: it is little endian in standard.
    #if self.openspdm_data[14] == 0xe3:
    #  lst = list(self.openspdm_data)
    #  t = lst[18]
    #  lst[18] = lst[17]
    #  lst[17] = t
    #  self.openspdm_data = bytes(lst)
    #
    #if self.openspdm_data[14] == 0x82:  # add w/a for GET_CERTIFICATE messgae : [offset] = 0
    #  lst = list(self.openspdm_data)
    return self.openspdm_data

  def show_spdm_msg(self):
    """ show spdm message
    """
    mctp_type, ver = self.data_buffer[0], self.data_buffer[1]
    if (mctp_type, ver) == (0x05, 0x10):
      hexcode   = "0x{:02X}".format(self.data_buffer[2])
      self.logger.info(" -- MCTP Type {:02x} SPDM MSG:({:02X}, {:02X}, {})".format(self.data_buffer[0], \
                     self.data_buffer[1], self.data_buffer[2], dict_SPDM_Code[hexcode]))

  def show(self):
    """ show data
    """
    # receive GET_VERSION: 0F 0A 01 00 00 00 C8 05 10 84 00 00 B0
    self.logger.info("-- Byte Count : 0x{:02x}".format(self.input_data[1]))
    self.logger.info("-- MCTP Header: {}".format(' '.join(['{:02x}'.format(x) for x in self.input_data[3:7]])))
    self.logger.info("-- PEC Byte   : 0x{:02x}".format(self.pec))
    self.show_spdm_msg()
    self.logger.info('  -- Data Buffer: ')
    log_list(self.logger, self.data_buffer, 32)



dict_SPDM_ResponseCode10 = { \
'0x01':'SPDM_DIGESTS',
'0x02':'SPDM_CERTIFICATE',
'0x03':'SPDM_CHALLENGE_AUTH',
'0x04':'SPDM_VERSION',
'0x60':'SPDM_MEASUREMENTS',
'0x61':'SPDM_CAPABILITIES',
'0x63':'SPDM_ALGORITHMS',
'0x7E':'SPDM_VENDOR_DEFINED_RESPONSE',
'0x7F':'SPDM_ERROR'
}

dict_SPDM_RequestCode10 = { \
'0x81':'SPDM_GET_DIGESTS',
'0x82':'SPDM_GET_CERTIFICATE',
'0x83':'SPDM_CHALLENGE',
'0x84':'SPDM_GET_VERSION',
'0xE0':'SPDM_GET_MEASUREMENTS',
'0xE1':'SPDM_GET_CAPABILITIES',
'0xE3':'SPDM_NEGOTIATE_ALGORITHMS',
'0xFE':'SPDM_VENDOR_DEFINED_REQUEST',
'0xFF':'SPDM_RESPOND_IF_READY'
}

dict_SPDM_ResponseCode11 = { \
'0x64':'SPDM_KEY_EXCHANGE_RSP',
'0x65':'SPDM_FINISH_RSP',
'0x66':'SPDM_PSK_EXCHANGE_RSP',
'0x67':'SPDM_PSK_FINISH_RSP',
'0x68':'SPDM_HEARTBEAT_ACK',
'0x69':'SPDM_KEY_UPDATE_ACK',
'0x6A':'SPDM_ENCAPSULATED_REQUEST',
'0x6B':'SPDM_ENCAPSULATED_RESPONSE_ACK',
'0x6C':'SPDM_END_SESSION_ACK'
}

dict_SPDM_RequestCode11 = { \
'0xE4':'SPDM_KEY_EXCHANGE',
'0xE5':'SPDM_FINISH',
'0xE6':'SPDM_PSK_EXCHANGE',
'0xE7':'SPDM_PSK_FINISH',
'0xE8':'SPDM_HEARTBEAT',
'0xE9':'SPDM_KEY_UPDATE',
'0xEA':'SPDM_GET_ENCAPSULATED_REQUEST',
'0xEB':'SPDM_DELIVER_ENCAPSULATED_RESPONSE',
'0xEC':'SPDM_END_SESSION'
}

dict_SPDM_Code = {**dict_SPDM_ResponseCode10, **dict_SPDM_RequestCode10, \
                **dict_SPDM_ResponseCode11, **dict_SPDM_RequestCode11}


