#!/usr/bin/env python3
# test_cpld.py
"""
  :platform: Linux, Windows
  :synopsis: This module is to test cpld SPDM protocol using OPENSPDM

  Introduction
  ============
  This module is used to test CPLD as SPDM-requester and responder

  Run SPDM Test
	=============
 
  Execution in command prompt::

    >python -m intel_pfr.test_cpld -get_setup   # get openspdm_execution.json file in work folder
    >python -m intel_pfr.test_cpld -s <openspdm_execution_json> # test in openspdm requester and responder loopback
    >python -m intel_pfr.test_cpld -req cpld -s <openspdm_execution_json>  # test CPLD as spdm requester
    >python -m intel_pfr.test_cpld -res cpld -s <openspdm_execution_json>  # test CPLD as spdm responder


  About OPENSPDM
  ==============

  OPENSPDM is open source project emulating SPDM devices. Refer 611974 device attestation chapter for preparation. 
	Refer OPENSPDM GitHub link  `openspdm <https://github.com/jyao1/openspdm>`_. for detail.

"""
# this is to test CPLD using openspdm-responnder
import socket, sys, time, os, argparse, shutil
import subprocess, json

import logging
logger = logging.getLogger(__name__)

from array import array
from intel_pfr import mctp_spdm, spdm

from intel_pfr.aardvark import smb_avark as avktool

PORT_REQUESTER = 2324
PORT_RESPONDER = 2325

CHUNK_SIZE = 4096
TIMEOUT    = 18

#define message for spdm requester
dict_spdm_req_1p0 = { \
'SPDM_GET_DIGESTS'           : 0x81,
'SPDM_GET_CERTIFICATE'       : 0x82,
'SPDM_CHALLENGE'             : 0x83,
'SPDM_GET_VERSION'           : 0x84,
'SPDM_GET_MEASUREMENTS'      : 0xE0,
'SPDM_GET_CAPABILITIES'      : 0xE1,
'SPDM_NEGOTIATE_ALGORITHMS'  : 0xE3,
'SPDM_VENDOR_DEFINED_REQUEST': 0xFE,
'SPDM_RESPOND_IF_READY'      : 0xFF}

#define message for spdm responder
dict_spdm_res_1p0 = { \
'SPDM_VERSION'        : 0x04,
'SPDM_CAPABILITIES'   : 0x61,
'SPDM_DIGESTS'        : 0x01,
'SPDM_CERTIFICATE'    : 0x02,
'SPDM_CHALLENGE_AUTH' : 0x03,
'SPDM_MEASUREMENTS'   : 0x60,
'SPDM_ALGORITHMS'     : 0x63,
'SPDM_VENDOR_DEFINED_RESPONSE': 0x7E,
'SPDM_ERROR'          : 0x7F}


lst_req_msg = [b'Client Hello']
for k in dict_spdm_req_1p0:
  lst_req_msg.append(b'\x05\x10'+bytes.fromhex('{:02x}'.format(dict_spdm_req_1p0[k])))
lst_req_msg.append(b'\x00\x00\x00\x00')

lst_res_msg = [b'Server Hello']
for k in dict_spdm_res_1p0:
  lst_res_msg.append(b'\x05\x10'+bytes.fromhex('{:02x}'.format(dict_spdm_res_1p0[k])))

transmit_cmd  = [b'\x00\x00\x00\x01', b'\x00\x00\xde\xad', b'\x00\x00\xff\xfe']
transportType = b'\x00\x00\x00\x01'
transmit_head = [i+transportType for i in transmit_cmd]

STOP_TRANSMIT   = b'\x00\x00\xff\xfe' + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x00'

STOP_COUNT = 2  # this only apply to CPLD test.

def config_log(logfile):
  """ config log file include a Filehandler and a Streamhandler

  """
  logging.basicConfig(level=logging.DEBUG,
                    #format='s',
                    #format='%(asctime)s - %(levelname)s [%(filename)s]: %(name)s %(funcName)20s - Message: %(message)s',
                    #datefmt='%d.%m.%Y %H:%M:%S',
                    handlers= [
                      logging.FileHandler(logfile, mode='w'),
                      logging.StreamHandler()
                    ]
                  )

def print_lst(fh, lst, num_per_line):
  """ print long list

  :param fh: log file handler
  :param lst: long list to be print
  :param num_per_line: number of items per line
  """
  cnt = 0
  fh.write('\n    ')
  for i in lst:
    fh.write(i + ' ')
    cnt += 1
    if cnt >=num_per_line:
      fh.write('\n    ')
      cnt = 0
  fh.write('\n----\n')


class Run_SPDM_Test(object):
  """ class for spdm test execution using OPENSPDM

  """
  def __init__(self, test_setup_json):
    with open(test_setup_json, 'r') as f:
      self.env = json.load(f)
    # initialize two dictionary
    self.dict_spdm_requester = {}
    self.dict_spdm_responder = {}

  def setup_test(self, requester, responder):
    """ setup requester and responder """
    if requester.lower() not in ('openspdm', 'cpld') or responder.lower() not in ('openspdm', 'cpld'):
      logger.error("-- wrong entry: should be either 'cpld' or 'openspdm' ")
    self.req = requester.lower()
    self.res = responder.lower()

    self.logfile = 'run_spdm_req-{a}-res-{b}.log'.format(a=requester, b=responder)
    config_log(self.logfile)

    self.get_version_count = 0  # stop if GET_VERSION repeat two times

  def run_test(self):
    """ run spdm test between requester and responder
     self.req
    """
    self.run_responder()
    self.run_requester()

    self.dict_spdm_requester = {}
    self.dict_spdm_responder = {}
    self.stop_transmit = False

    while not self.stop_transmit:
      print ("-- entered loop ...")
      self.data_req = []
      self.data_res = []
      self.raw_mctp_req = array('B', [])
      self.raw_mctp_res = array('B', [])

      while not self.stop_transmit:
        self.requester_to_res()
        self.process_mctp_requester()

        self.responder_to_req()
        self.process_mctp_responder()

        if self.get_version_count >= STOP_COUNT:
          self.stop_transmit = True

        #openspdm - openspdm
        if (self.raw_mctp_req.tobytes() == STOP_TRANSMIT):
          self.stop_transmit = True

    print("--Done: Saved data to file")

    #print(dict_spdm_requester)
    #spdm_requester = spdm.SPDM_REQUESTER(self.dict_spdm_requester)
    #spdm_requester.set_responder_pubkey(r'C:\shuang4\Work\openspdm-master\Build\DEBUG_VS2019\X64\EcP384\end_res_public_key.pem')
    #spdm_requester.verify_M2()
    #spdm_requester.verify_L2()
    #spdm_requester.show()

    #print(dict_spdm_responder)
    #spdm_responder = spdm.SPDM_RESPONDER(dict_spdm_responder)
    #spdm_responder.show()
    self.close_test()


  def run_requester(self):
    """ run spdm requester """
    if self.req == 'openspdm':
      logger.info('-- run openspdm requester')
      req_addr = ('localhost', PORT_REQUESTER)
      print("---listen_to_requester {} port {}".format(*req_addr))
      # Create a TCP/IP socket
      self.sock_req = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

      req_cmdline= self.env['cmd_openspdm_requester']
      if self.res == 'openspdm':
        dir = self.env['openspdm_dir']
      if self.res == 'cpld':
        dir = self.env['openspdm_req_dir']
      self.req_rc = subprocess.run("start cmd /K " + req_cmdline, cwd = dir, shell=True, stdout=subprocess.DEVNULL)

      #print("-- bind to requester ...")
      self.sock_req.bind(req_addr)
      # Listen for incoming connections
      self.sock_req.listen()
      #print('waiting for a connection')
      self.req_conn, self.req_c_addr = self.sock_req.accept()
      print('-- connection requester done from: ', self.req_c_addr)

      logger.info('-- run_requester_dir: {}'.format(dir))
      if self.res == 'cpld':
        self.hello_to_requester()

    if self.req == 'cpld':
      # avk is aardvark tool object instance
      print('-- set aardvark for CPLD ...')
      self.avk = avktool.mctp_avark(0x05)


  def run_responder(self):
    """ run spdm responder """
    if self.res == 'openspdm':
      logger.info('-- run openspdm responder')

      res_cmdline= self.env['cmd_openspdm_responder']
      dir = self.env['openspdm_dir']
      self.res_rc = subprocess.run("start cmd /K " + res_cmdline, cwd = dir, shell=True)
      time.sleep(1)
      # Create a TCP/IP socket
      self.sock_res = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # Connect the socket to the port where the server is listening
      res_server_addr = ('localhost', PORT_RESPONDER)
      print('-- connecting responder server to {} port {}'.format(*res_server_addr))
      self.sock_res.connect(res_server_addr)
      print('-- connected to responder server to {} port {}'.format(*res_server_addr))
      logger.info('-- run_responder_dir: {}'.format(dir))

      if self.req == 'cpld':
        self.hello_to_responder()

    if self.res == 'cpld':
      self.avk = avktool.mctp_avark(0x05)
      # CPLD sends requester mctp in default... waiting for first requester MCTP and wait for 'delay_time' to get ready
      cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())
      if cpld_s.spdm_code == 0x84:
        cpld_s.show()
      time.sleep(int(self.env['delay_time']))


  def hello_to_responder(self):
    # finish first handshake...
    self.sock_res.sendall(spdm.start_hello())
    logger.info('--- Hello to openspdm responder: {}'.format(spdm.start_hello()) )
    say_hello = True
    while say_hello:
      try:
        datachunk_s = self.sock_res.recv(CHUNK_SIZE)
      except:
        break
      if not datachunk_s:
        break  # no more data coming in, so break out of the while loop
      print("-- received from openspdm-responder:", datachunk_s)
      if b'Server Hello!\x00' in datachunk_s:
        say_hello = False


  def hello_to_requester(self):
    # finish first handshake to openspdm requester ...
    say_hello = True
    while say_hello:
      try:
        datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
      except:
        break
      if not datachunk_q:
        break  # no more data coming in, so break out of the while loop
      print("-- received from openspdm-requester:", datachunk_q)
      if b'Client Hello!\x00' in datachunk_q:
        say_hello = False

    logger.info('--- Hello to openspdm requester: {}'.format(spdm.server_hello()))
    self.req_conn.sendall(spdm.server_hello())


  def requester_to_res(self):
    """ SPDM.requester to SPDM.responder
     Deliver packet from self.req --> self.res
    """
    if (self.req, self.res) == ('openspdm', 'openspdm'):
      # openspdm --> openspdm
      while True:
        try:
          datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
        except:
          break
        if not datachunk_q:
          break # no more data coming in, so break out of the while loop
        self.sock_res.sendall(datachunk_q)
        logger.info("-- REQ-->RES datachunk: {}".format(datachunk_q))
        self.raw_mctp_req.extend(datachunk_q)  # track single mctp message
        logger.info("**** raw_mctp_req.tobytes(): {}".format(self.raw_mctp_req.tobytes()))
        if any(item in datachunk_q for item in lst_req_msg):
          break

    if (self.req, self.res) == ('cpld', 'openspdm'):
      # cpld --> openspdm
      cpld_r = mctp_spdm.MCTP_CPLD(self.avk.recv())
      cpld_r.show()
      if cpld_r.spdm_code == dict_spdm_req_1p0['SPDM_GET_VERSION']:
        self.get_version_count += 1
        logger.info('\n--- GET_VERSION_CNT = {}'.format(self.get_version_count))
      cpld_msg = cpld_r.get_openspdm_data()
      datachunk_q = cpld_msg
      logger.info("\n-- send to openspdm responder message:{}".format(' '.join(['{:02x}'.format(i) for i in datachunk_q])))
      self.sock_res.sendall(datachunk_q)
      self.raw_mctp_req.extend(datachunk_q)  # track single mctp message
      self.data_req.append(self.raw_mctp_req)  # append to data_req for all message


    if (self.req, self.res) == ('openspdm', 'cpld'):
      # openspdm --> cpld
      openspdm_msg_done = False
      while not openspdm_msg_done:
        try:
          datachunk_q = self.req_conn.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
          self.raw_mctp_req.extend(datachunk_q)  # add chunk to your already collected data
        except:
          break
        if not datachunk_q:
          break # no more data coming in, so break out of the while loop
        msg_bytes = self.raw_mctp_req.tobytes()
        if any(item in msg_bytes for item in lst_req_msg):
          openspdm_msg_done = True

      # send to CPLD after done
      logger.info('-- mctp_req: {}'.format(' '.join(['{:02x}'.format(i) for i in self.raw_mctp_req.tobytes()])))
      cpld_q = mctp_spdm.MCTP_SOCKET(self.raw_mctp_req.tobytes())
      cpld_q.show()

      if (self.raw_mctp_req.tobytes() == STOP_TRANSMIT):
          self.stop_transmit = True
          logger.error('-- Protocol Error: cpld sends requester mctp')
          return

      logger.info("-- decode spdm message --")
      spdm_msg = spdm.egs_spdm(self.raw_mctp_req.tobytes())
      spdm_msg.decode_message()

      smb_data = cpld_q.get_smbus_data()
      if isinstance(smb_data, (bytes, bytearray)):
        logger.info('-- send to cpld (responder) data: {}'.format(' '.join(['{:02x}'.format(i) for i in smb_data])))
        self.avk.send(smb_data)
      elif isinstance(smb_data, list):
        for segdata in smb_data:
          logger.info("-- segdata over smbus: {}".format(' '.join(['{:02x}'.format(i) for i in segdata])))
          self.avk.send(segdata)

      # accumulate data for post process
      self.data_req.append(self.raw_mctp_req)  # append raw_mctp_res to for all


  def responder_to_req(self):
    """ SPDM responder to SPDM requester """
    if self.stop_transmit: return
    if (self.req, self.res) == ('openspdm', 'openspdm'):
      """ responder to requester """
      while True:
        try:
          datachunk_s = self.sock_res.recv(CHUNK_SIZE) # reads data chunk from the socket in batches using method recv() until it returns an empty string
          #print('-- datachunk_s: {}'.format(datachunk_s))
        except:
          break
        if not datachunk_s:
          break  # no more data coming in, so break out of the while loop

        self.req_conn.sendall(datachunk_s)
        logger.info("-- RES-->REQ datachunk: {}".format(datachunk_s))
        self.raw_mctp_res.extend(datachunk_s)  # add chunk to your already collected data
        # check spdm message code switch to req
        if any(item in datachunk_s for item in lst_res_msg):
          break

    if (self.req, self.res) == ('cpld', 'openspdm'):
      # openspdm (res) --> cpld (req)
      openspdm_msg_done = False
      while (not openspdm_msg_done):
        try:
          datachunk_s = self.sock_res.recv(CHUNK_SIZE)
          self.raw_mctp_res.extend(datachunk_s)  # add chunk to your already collected data
        except:
          break
        if not datachunk_s:
          break  # no more data coming in, so break out of the while loop

        msg_bytes = self.raw_mctp_res.tobytes()
        #print('-- mctp_res:', self.raw_mctp_res.tobytes())
        if any(item in msg_bytes for item in lst_res_msg):
          openspdm_msg_done = True
          # send to CPLD after done
          logger.info('-- mctp_res: {}'.format(' '.join(['{:02x}'.format(i) for i in self.raw_mctp_res.tobytes()])))
          cpld_r = mctp_spdm.MCTP_SOCKET(self.raw_mctp_res.tobytes())
          cpld_r.show()
          logger.info("-- decode spdm message --")
          spdm_msg = spdm.egs_spdm(self.raw_mctp_res.tobytes())
          spdm_msg.decode_message()

          smb_data = cpld_r.get_smbus_data()
          if isinstance(smb_data, (bytes, bytearray)):
            logger.info('-- send to cpld (requester) data: {}'.format(' '.join(['{:02x}'.format(i) for i in smb_data])))
            self.avk.send(smb_data)
          elif isinstance(smb_data, list):
            for segdata in smb_data:
              logger.info("-- segdata over smbus: {}".format(' '.join(['{:02x}'.format(i) for i in segdata])))
              self.avk.send(segdata)

          self.data_res.append(self.raw_mctp_res)  # append raw_mctp_res to for all

    if (self.req, self.res) == ('openspdm', 'cpld'):
      # cpld-res --> openspdm-res
      print("-- recv data from CPLD...")
      cpld_s = mctp_spdm.MCTP_CPLD(self.avk.recv())  # CPLD is responder
      cpld_s.show()
      cpld_msg = cpld_s.get_openspdm_data()
      datachunk_s = cpld_msg
      logger.info("\n-- send to openspdm requester message:{}".format(' '.join(['{:02x}'.format(i) for i in datachunk_s])))

      self.req_conn.sendall(datachunk_s)
      self.raw_mctp_res.extend(datachunk_s)  # track single mctp message
      self.data_res.append(self.raw_mctp_res)  # append to data_req for all message


  def process_mctp_requester(self):
    # process requester MCTP packet
    logger.info("-- process mctp_requester ...")
    print(self.raw_mctp_req.tobytes())
    if self.stop_transmit: return

    mctp_data = mctp_spdm.MCTP_SOCKET(self.raw_mctp_req.tobytes())
    logger.info('\n-- To Responder: {}-responder'.format(self.res))
    mctp_data.show()
    input_data = mctp_data.get_spdm_data()

    if input_data is not None:
     spdm_msg = spdm.egs_spdm(input_data)
     spdm_msg.decode_message()

     print(mctp_data.spdm_msgcode)
     if mctp_data.spdm_msgcode in self.dict_spdm_requester.keys():
       self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
     else:
       self.dict_spdm_requester[mctp_data.spdm_msgcode] = []
       self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

     if mctp_data.spdm_msgcode in self.dict_spdm_responder.keys():
       self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
     else:
       self.dict_spdm_responder[mctp_data.spdm_msgcode] = []
       self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

    self.data_req.append(self.raw_mctp_req)  # append to data_req for all message
    self.raw_mctp_req = array('B', [])  # clear single message


  def process_mctp_responder(self):
    """ process responder MCTP packet"""
    if self.stop_transmit: return
    logger.info("-- process mctp_responder ...")

    mctp_data = mctp_spdm.MCTP_SOCKET(self.raw_mctp_res.tobytes())
    logger.info('\n-- To Requester: {}-requester'.format(self.req))
    mctp_data.show()
    input_data = mctp_data.get_spdm_data()

    #if self.res == 'cpld':
    #  input_data = self.raw_mctp_res.tobytes()

    if input_data is not None:
      spdm_msg = spdm.egs_spdm(input_data)
      spdm_msg.decode_message()

      print(mctp_data.spdm_msgcode)
      if mctp_data.spdm_msgcode in self.dict_spdm_requester.keys():
        self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
      else:
        self.dict_spdm_requester[mctp_data.spdm_msgcode] = []
        self.dict_spdm_requester[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

      if mctp_data.spdm_msgcode in self.dict_spdm_responder.keys():
        self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])
      else:
        self.dict_spdm_responder[mctp_data.spdm_msgcode] = []
        self.dict_spdm_responder[mctp_data.spdm_msgcode].append(mctp_data.data_buffer[1:])

    self.data_res.append(self.raw_mctp_res)  # append raw_mctp_res to for all
    if self.raw_mctp_res.tobytes() == STOP_TRANSMIT:
      self.stop_transmit = True
    else:
      self.raw_mctp_res = array('B', [])  # clear for next message


  def close_test(self):
    """ do close actions for the test """
    if self.req == 'openspdm': self.req_conn.close()
    if self.res == 'openspdm': self.sock_res.close()
    if (self.req == 'cpld') or (self.res == 'cpld'):
      self.avk.close()
    logging.shutdown()

def main(args):
  """ test CPLD command line options
  """
  parser = argparse.ArgumentParser(description="-- Run SPDM validation test ")
  parser.add_argument('-get_setup', action='store_true', help="copy execution json file to work folder")
  parser.add_argument('-s', '--setup', metavar="[setup json file]",  dest='setup_json', help='openspdm execution json file')
  parser.add_argument('-req', metavar="[spdm requester]",  dest='spdm_req', default = 'openspdm', help="set SPDM requester: either openspdm or cpld, default is openspdm ")
  parser.add_argument('-res', metavar="[spdm responder]",  dest='spdm_res', default = 'openspdm', help="set SPDM responder: either openspdm or cpld, default is openspdm ")

  args = parser.parse_args(args)
  if args.get_setup:
    print('-- copy the execution json file to {}'.format(os.getcwd()))
    src_json_file = os.path.join(os.path.dirname(__file__), 'json', 'openspdm_execution.json')
    dst_json_file = os.path.join(os.getcwd(), 'openspdm_execution.json')
    shutil.copyfile(src_json_file, dst_json_file)

  print(args)

  mytest = Run_SPDM_Test(args.setup_json)
  mytest.setup_test(args.spdm_req, args.spdm_res)
  mytest.run_test()

if __name__ == '__main__':
  main(sys.argv[1:])

