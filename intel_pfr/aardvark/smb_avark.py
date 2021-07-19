#!/usr/bin/env python3
# smb_avark module
"""
  :platform: Linux, Windows
  :synopsis: i2c driver wrapper to send and receive traffic to CPLD using aadvark tool

  Aardvark is I2C/SPI host adapter, refer https://www.totalphase.com/products/aardvark-i2cspi/

  CPLD slave address is 0x70

"""
import binascii, warnings, logging, datetime, time
from array import array, ArrayType
from intel_pfr.aardvark import aardvark_py as avark

CPLD_SLAVE_ADDR = 0x70

BUS_TIMEOUT      = 100  # ms
BUS_POLL_TIMEOUT = 10   # ms
I2C_BITRATE      = 100  # 100 KHz

BUFFER_SIZE      = 65535 # Tx/Rx buffer size

STATUS_OPEN   =  1
STATUS_CLOSED = -1
STATUS_NOTSET =  0

import logging
logger = logging.getLogger(__name__)

def detect():
  """ detect aardvark device """
  print("Detecting Aardvark adapters...")

  # Find all the attached devices
  (num, ports, unique_ids) = avark.aa_find_devices_ext(16, 16)
  rtn = []
  if num > 0:
    print("%d device(s) found:" % num)
    # Print the information on each device
    for i in range(num):
      port      = ports[i]
      unique_id = unique_ids[i]
      # Determine if the device is in-use
      inuse = "(avail)"
      if (port & avark.AA_PORT_NOT_FREE):
        inuse = "(in-use)"
        port  = port & ~(avark.AA_PORT_NOT_FREE)
      # Display device port number, in-use status, and serial number
      print("    port = %d   %s  (%04d-%06d)" %
           (port, inuse, unique_id // 1000000, unique_id % 1000000))
      if (inuse is "(avail)"):
        rtn.append((True, port, inuse))
      else:
        rtn.append((False, port, inuse))
  else:
    print("No devices found.")
  return rtn


class mctp_avark(object):
  """ class for aardvark configuration as PCIe End Point device on SMBus

  :param device_addr: destination address

  """
  def __init__(self, device_addr):
    self.device_addr = device_addr
    self.cpld_slave_addr = CPLD_SLAVE_ADDR
    self.open()

  def open(self, port=0, bitrate=I2C_BITRATE):
    avark.aa_i2c_free_bus(port)
    avark.aa_close(port)  # close port 0 first
    self.logger = logging.getLogger(__name__)
    self.port    = port
    self.status  = STATUS_NOTSET
    self.bitrate = bitrate
    self.handle = avark.aa_open(self.port)
    if self.handle <= 0:
      self.logger.error("Unable to open Aardvark device on port %d" % port)
      self.logger.error("Error code = %d" % self.handle)
      return False
    else:
      self.status = STATUS_OPEN

    # ensure it is configured as I2C subsystem is enabled
    avark.aa_configure(self.handle, avark.AA_CONFIG_SPI_I2C)
    avark.aa_i2c_pullup(self.handle, avark.AA_I2C_PULLUP_BOTH)
    avark.aa_i2c_bitrate(self.handle, I2C_BITRATE)
    avark.aa_i2c_bus_timeout(self.handle, BUS_TIMEOUT)
    avark.aa_i2c_slave_enable(self.handle, self.device_addr, 0, 0)  # enable slave mode

  def recv(self):
    """ slave read data from Aardvark tool from CPLD SPDM SMBus interface

    """
    num_bytes = 0
    data_recv = array('B', [])
    self.logger.info('-- recv waiting smbus data')
    #t1=time.time()
    #cnt = 0
    while(num_bytes <= 0):
      result = avark.aa_async_poll(self.handle, BUS_POLL_TIMEOUT)
      if result == avark.AA_ASYNC_I2C_READ:
        (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)
      #time.sleep(0.01)
      #cnt += 1

    if num_bytes == 0:
      warnings.warn(UserWarning("i2c: Fail to get any response"))
    bdata=data_recv.tobytes()
    lst=' '.join(['{:02x}'.format(i) for i in bdata])
    self.logger.info("num_bytes = {}, addr = 0x{:02X}, \n****CPLD: data_recv (in hex) = {}".format(num_bytes, addr, lst))
    return data_recv

  def send(self, data_send):
    """
    send data bytes from Aardvark tool

    :param data_send: data send out in bytearray
    :type bytes: bytes, bytearray

    append PEC byte::

      https://crccalc.com/
      In Aardvark: Master - addr 0x70
      SPDM_VERSION message bytes: 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10 14
      Calculate PEC code as: "E0 0F 0E 0B 00 00 00 C8 05 10 04 00 00 00 01 00 10" --> 0x14

    """
    num_bytes = 0
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.cpld_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))
    self.logger.info('-- err_flag: {}, length = {}'.format(err_flag, write_byte_count))


  def send_recv(self, data_send):
    """ AFM: DeviceAddr=0x02, UUID=0x0001 """
    # INTERVAL_TIMEOUT = 1000
    num_bytes = 0
    data_recv = array('B', [])
    (err_flag, write_byte_count) = avark.aa_i2c_write_ext(self.handle, self.cpld_slave_addr, avark.AA_I2C_NO_FLAGS, array('B', data_send))

    result = avark.aa_async_poll(self.handle, BUS_POLL_TIMEOUT)
    if result == avark.AA_ASYNC_I2C_READ:
      (num_bytes, addr, data_recv) = avark.aa_i2c_slave_read(self.handle, BUFFER_SIZE)

    if num_bytes == 0:
      warnings.warn(UserWarning("i2c: Fail to get any response"))
    self.logger.info("err_flag = {}, slave_addr = 0x{:02X}, write_byte_count={}, data_send = {}".format(err_flag, self.cpld_slave_addr, write_byte_count, data_send))
    self.logger.info("num_bytes = {}, dest_addr = 0x{:02X}, data_recv = {}".format(num_bytes, self.device_addr, data_recv))
    return (err_flag, write_byte_count, data_send, data_recv)

  def free(self):
    """ free i2c bus """
    rtn = avark.aa_i2c_free_bus(self.port)
    return rtn

  def close(self):
    """ close Aardvark tool driver """
    self.free()
    rtn = avark.aa_close(self.port)
    if (rtn > 0):
      print("-- aardvark device is closed: {}".format(rtn))


