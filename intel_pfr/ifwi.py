#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    This module is to analysis and customize IFWI image::

     * add cpld update capsule to IFWI staging area
     * extract PFR provision data from bios region
     * update BMC PFM active offset

    command line execution::

     >python -m intel_pfr.ifwi -i <pfr_ifwi_image>
     >python -m intel_pfr.ifwi -i <pfr_ifwi_image> -show_prov

     # update BMC active pfm offset
     >python -m intel_pfr.ifwi -i <pfr_ifwi_image> -bmc_pfm <bmc_active_offset>

     # example: from BMC offset from 0x80000 to 0x1FC00000, a new ifwi image will be generated.
     >python -m intel_pfr.ifwi -i <pfr_ifwi_image> -bmc_pfm 0x1fc0000


"""
from __future__ import print_function
from __future__ import division

__license__   = "Intel Confidential"
__author__    = "Scott Huang (scott.huang@intel.com)"
__revision__  = "$Id: $"
__docformat__ = 'reStructuredText'

import sys, os, struct, hashlib, re, binascii, time, datetime, getopt, argparse
import json, codecs, struct, shutil, collections, base64
from xml.dom import minidom
from functools import partial
import logging

from intel_pfr import pfm

_PFRS_TAG = '__PFRS__'
_PFRS_KEYS =  ( "struct_ID",
                "struct_ver",
                "rsvd1",
                "elem_size",
                "cntl_flags",
                "rsvd2",
                "cpld_smbaddr",
                "pch_active",
                "pch_recovery",
                "pch_staging",
                "bmc_active",
                "bmc_recovery",
                "bmc_staging")

_PFRS_FMT = '<8sBBHI3sBIIIIII'

_KEYM_TAG = '__KEYM__'
_KEYM_KEYS = ('struct_ID',
              'struct_ver',
              'rsvd1',
              'keySigOffset',
              'rsvd2',
              'keyManifestVer',
              'KMSVN',
              'keyManifestID',
              'kmPubkey_Alg',
              'num_keydigest',
              'keyhash_usage1',
              'keyhash_Alg1',
              'keyhash_size1',
              'keyhash_buffer1',
              'keyhash_usage2',
              'keyhash_Alg2',
              'keyhash_size2',
              'keyhash_buffer2')

_KEYM_STRUCT_ID   = b'__KEYM__'
_KEYM_STRUCT_VER  = 0x21
_KEYM_SIGOFFSET_3 = 0x90
_KEYM_SIGOFFSET_2 = 0x70
_KEYM_USAGE_PFR   = 0x10
_KEYM_HASH_ALG_2  = 0x000B
_KEYM_HASH_ALG_3  = 0x000C
_KEYM_HASH_SIZE_2 = 0x0020
_KEYM_HASH_SIZE_3 = 0x0030

_KEYM_FMT_2 = '<8sB3sH3sBBBHHQHH32sQHH32s'
_KEYM_FMT_3 = '<8sB3sH3sBBBHHQHH48sQHH48s'


class Agent(object):
  """ extract PFR provision UFM data from PFR BIOS binary image

  """
  def __init__(self, input_img):
    self.logger   = logging.getLogger(__name__)
    self._image   = input_img
    self._pfr_ver = 0
    self._pfrs = {}
    self._keym = {}

  def get_pfrs_value(self):
    """ get provision data

    extract pfr offset provision UFM data from __PFRS__ structure
    """
    #self.logger.info("-- get_pfrs_value ")
    with open(self._image, 'rb') as f:
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(str.encode(_PFRS_TAG)), f.read())]
      staddr = int(lst_addr[0], 0)
      self.pfrs_start = staddr
      f.seek(staddr)
      tmp_lst = struct.unpack(_PFRS_FMT, f.read(struct.calcsize(_PFRS_FMT)))
      #print(tmp_lst)
      for (k,v) in zip(_PFRS_KEYS, tmp_lst):
        if isinstance(v, bytes) and (k is not 'struct_ID'): v=v.hex()
        if isinstance(v, int): v=hex(v)
        self._pfrs[k]=v

  def get_keym_value(self):
    """ extract root public key hash from __KEYM__ structure

    """
    #self.logger.info("-- get_keym_value ")
    with open(self._image, 'rb') as f:
      lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(str.encode(_KEYM_TAG)), f.read())]
      staddr=int(lst_addr[0], 0)
      f.seek(staddr)
      keymtag = f.read(8)
      (ver, rsvd, keysigoffset)=struct.unpack('<B3sH', f.read(6))
      #print('-- keymtag :', keymtag)
      if (keymtag == _KEYM_STRUCT_ID) and (ver == _KEYM_STRUCT_VER):
        if keysigoffset == _KEYM_SIGOFFSET_2:
          self._pfr_ver = 2.0
          f.seek(staddr)
          tmp_lst = struct.unpack(_KEYM_FMT_2, f.read(struct.calcsize(_KEYM_FMT_2)))

        if keysigoffset == _KEYM_SIGOFFSET_3:
          self._pfr_ver = 3.0
          f.seek(staddr)
          tmp_lst = struct.unpack(_KEYM_FMT_3, f.read(struct.calcsize(_KEYM_FMT_3)))

        for (k, v) in zip(_KEYM_KEYS, tmp_lst):
          if (k is not 'struct_ID') and isinstance(v, (bytes, bytearray)): v=v.hex()
          if isinstance(v, int): v=hex(v)
          self._keym[k] = v
        if int(self._keym['keyhash_usage2'], 0) == 0x10:
          self._keyhash = self._keym['keyhash_buffer2']
        if int(self._keym['keyhash_usage1'], 0) == 0x10:
          self._keyhash = self._keym['keyhash_buffer1']

  def get_prov_data(self):
    """ get provision data

    extract root public key hash from __KEYM__ structure
    extract pfr offset provision UFM data from __PFRS__ structure
    """
    self.get_pfrs_value()
    self.get_keym_value()

  def show(self):
    """ log structure data """
    if self._pfr_ver == 0:
      self.get_prov_data()
    for k in _KEYM_KEYS:
      self.logger.info("--{:20s}: {}".format(k, self._keym[k]))
    self.logger.info("-- PFR root public key hash: {} \n".format(self._keyhash))
    for k in _PFRS_KEYS:
      self.logger.info("--{:20s}: {}".format(k, self._pfrs[k]))


ACTV_PFM_SIZE  = 0x10000
RECV_CAP_SIZE  = 0x1400000
STAG_CAP_SIZE  = 0x1400000

class IFWI(object):
  """ class for IFWI image operation

  :param ifwi_image: pfr ifwi image

  """
  def __init__(self, ifwi_image):
    self.logger   = logging.getLogger(__name__)
    self.ifwi_image = ifwi_image
    obj=Agent(ifwi_image)
    obj.get_prov_data()
    self.pfrs = obj._pfrs
    self.keym = obj._keym
    self.pfrs_start = obj.pfrs_start # PFRS_ start offset
    self.pfr_rk_hash = obj._keyhash
    with open(self.ifwi_image, 'rb') as f:
      f.seek(int(self.pfrs['pch_active'], 0))
      self.act_pfm = pfm.PFM(f.read(ACTV_PFM_SIZE))
      f.seek(int(self.pfrs['pch_recovery'],0))
      self.rcv_pfm = pfm.PFM(f.read(RECV_CAP_SIZE))
      f.seek(int(self.pfrs['pch_staging'], 0))
      self.stg_pfm = pfm.PFM(f.read(STAG_CAP_SIZE))


  def update_bmc_active(self, bmc_active_offset):
    """ update BMC active PFM offset

    :param bmc_active_offset: BMC active PFM offset

    """
    self.new_ifwi_image = os.path.splitext(self.ifwi_image)[0]+"_update.bin"
    self.bmc_act_offset = self.pfrs_start + struct.calcsize('<8sBBHI3sBIII')
    with open(self.ifwi_image, 'rb') as f1, open(self.new_ifwi_image, 'wb') as f2:
      f1.seek(0)
      f2.write(f1.read(self.bmc_act_offset))
      f2.write(struct.pack('<I', int(bmc_active_offset, 0) ) )
      f1.seek(self.bmc_act_offset+4)
      f2.write(f1.read())

  def add_capsule(self, start_addr, capsule_image):
    """ add capsule image to ifwi image

    This function can be used to include staging capsule to pfr ifwi image.
    or adding cpld signed update capsule to PCH/CPU SPI image

    :param start_addr: start address of signed capsule
    :param capsule_image: capsule image file to be added

    """
    self.new_ifwi_image = os.path.splitext(self.ifwi_image)[0]+"_update.bin"
    shutil.copy(self.ifwi_image, self.new_ifwi_image)
    with open(self.new_ifwi_image, 'r+b') as fd1, open(capsule_image, 'rb') as fd2:
      fd1.seek(start_addr)
      fd1.write(fd2.read())

  def get_rcv_capsule(self):
    self.rcv_cap = os.path.splitext(self.ifwi_image)[0]+"_rcv_cap.bin"
    with open(self.ifwi_image, 'rb') as f1, open(self.rcv_cap, 'wb') as f2:
      f1.seek(int(self.pfrs['pch_recovery'],0))
      f2.write(f1.read(RECV_CAP_SIZE))

  def show(self):
    msg  = '\n-- IFWI provision:\n active: {}, recovery: {}, staging: {}'.format(self.pfrs['pch_active'], self.pfrs['pch_recovery'],self.pfrs['pch_staging'])
    msg += '\n-- BMC provision:\n active: {}, recovery: {}, staging: {}'.format(self.pfrs['bmc_active'], self.pfrs['bmc_recovery'],self.pfrs['bmc_staging'])
    msg += '\n-- PFR root public key hash: {}'.format(self.pfr_rk_hash)
    self.logger.info(msg)
    self.logger.info('-- Active PFM:\n')
    self.act_pfm.show()
    if self.rcv_pfm.no_pfm_tag is False:
      self.logger.info('\n-- Recovery Capsule:\n')
      self.rcv_pfm.show()
    else:
      self.logger.info('\n-- No recovery capsule found.')

    if self.stg_pfm.no_pfm_tag is False:
      self.logger.info('\n-- Staging Capsule:\n')
      self.stg_pfm.show()
    else:
      self.logger.info('\n-- No staging capsule found.')


def main(args):
  parser = argparse.ArgumentParser(description='PFR IFWI module analysis')
  parser.add_argument('-show_prov', action='store_true', help='show provision information from BIOS')
  parser.add_argument('-i', '--input_image',      metavar="[input image]",    dest='input_img', help='input ifwi pfr image file')
  parser.add_argument('-log', '--logfile', metavar="[log file name]", dest='logfile', default=None, help="log file name, optional")
  parser.add_argument('-bmc_pfm', '--bmc_active_pfm',  metavar="[bmc active pfm offset]", dest='bmc_active', default=None, help='bmc active offset')

  args = parser.parse_args(args)
  #print(args)

  if args.logfile != None:
    logging.basicConfig(level=logging.DEBUG,
                    handlers= [
                      logging.FileHandler(args.logfile, mode='w'),
                      logging.StreamHandler()
                    ]
                  )
  else:
    logging.basicConfig(level=logging.DEBUG,
                    handlers= [
                      logging.StreamHandler()
                    ]
                  )

  ifwiobj = IFWI(args.input_img)
  ifwiobj.show()

  if args.show_prov:
    print("-- show provision")
    Agent(args.input_img).show()

  if args.bmc_active != None:
    ifwiobj.update_bmc_active(args.bmc_active)
    newobj = IFWI(ifwiobj.new_ifwi_image)
    newobj.show()

if __name__ == '__main__':
  main(sys.argv[1:])
