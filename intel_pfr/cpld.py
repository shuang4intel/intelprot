#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
   :platform: Linux, Windows
   :synopsis: Python script to update CPLD unisgned capsule and sign it

   cpld module includes function to sign cpld capsule using intel_pfr.sign module.
   The unsigned recovery capsule is the pfr_cfm1_auto.rpd generated from Quartus.
   Then use both RK and CSK private keys to sign it.

   Sign CPLD recovery/staging capsule
   ==================================


   Sign in python console and script
   ---------------------------------

   code block::

     >>>from intel_pfr import cpld
     >>>mycpld = cpld.CPLD(unsigned_cap, rk_prv, csk_prv, csk_id)
     >>>mycpld.sign()


   Sign in command line
   --------------------

   python (or python3 for Linux) should be in system executable path.
   save the keys and unsigned capsule in work folder.
   It requires Python 3.6 or later Python

   command line::

     >python -m intel_pfr.cpld -h   # help
     >python -m intel_pfr.cpld -u <unsigned_capsule> -rk <root private key> -csk <csk private key> -cskid <csk id, optional> -o <output, optional>


"""
import os, sys, shutil, struct, argparse, pathlib
from collections import OrderedDict
from intel_pfr import sign, utility

_CPLD_CAP_PCTYPE  = 0   # pc_type for CPLD update capsule

BLK0_FMT = '<IIII32s48s32s'
BLK0_KEY = ['b0_tag', 'pc_len', 'pc_type', 'b0_rsvd1', 'hash256', 'hash384', 'b0_rsvd2']
BLK1_FMT = 'I12sIIII48s48s20sIIII48s48s20sI48s48sII48s48s'
BLK1_KEY_B1R   = ['b1_tag', 'b1_rsvd1', 'b1r_tag', 'b1r_curve', 'b1r_permission', 'b1r_keyid', 'b1r_pubX', 'b1r_pubY', 'b1r_rsvd2']
BLK1_KEY_B1CSK = ['b1csk_tag', 'b1csk_curve', 'b1csk_permission', 'b1csk_keyid', 'b1csk_pubX', 'b1csk_pubY', 'b1csk_rsvd1', 'b1csk_sig_magic', 'b1csk_sigR', 'b1csk_sigS']
BLK1_KEY_B1B0  = ['b1b0_tag', 'b1b0_sig_magic', 'b1b0_sigR', 'b1b0_sigS']

BLK1_KEY = BLK1_KEY_B1R + BLK1_KEY_B1CSK + BLK1_KEY_B1B0

BLK_SIGN_FMT = BLK0_FMT + BLK1_FMT
BLK_SIGN_KEY = BLK0_KEY + BLK1_KEY

# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val


class CPLD(object):
  """ class for cpld image operation

  :param unsigned_cap: unsigned cpld capsule name
  :param rk_prv: root private key in PEM format
  :param csk_prv: csk private key in PRM format
  :param csk_id: CSK ID, default is 0

  """
  def __init__(self, unsigned_cap, rk_prv, csk_prv, csk_id=0):
    self.unsigned_cap = unsigned_cap
    self.rk_prv  = rk_prv
    self.csk_prv = csk_prv
    self.csk_id  = csk_id

  def set_signed_cap(self, signed_cap_name):
    self.signed_cap = signed_cap_name

  def sign_capsule(self):
    mycpld = sign.Signing(self.unsigned_cap, _CPLD_CAP_PCTYPE, self.csk_id, self.rk_prv, self.csk_prv)
    mycpld.sign()


class UpdateCapsule(object):
  """
  class for process of signed update capsule
  """
  def __init__(self, signed_image):
    self.signed_image= signed_image
    self.cap_dict = ConfigDict()
    self.unsigned_cap = 'unsigned_cap.bin'

  def get_unsigned_cap(self, out_image=None):
    """ process a signed image
    """
    with open(self.signed_image, 'rb') as f:
      blk_data=f.read(1024)
    s = struct.calcsize(BLK_SIGN_FMT)
    lst_temp = struct.unpack(BLK_SIGN_FMT, blk_data[0:s])
    for (k, v) in zip(BLK_SIGN_KEY, lst_temp):
      self.cap_dict[k] = v
    """
    for k in BLK_SIGN_KEY:
      print(k, '=')
      if isinstance(self.cap_dict[k], int):
        print(hex(self.cap_dict[k]))
      else:
        print(self.cap_dict[k].hex())
    """
    pc_len = self.cap_dict['pc_len']
    with open(self.signed_image, 'rb') as f, open(self.unsigned_cap, 'wb') as f1:
      f.seek(1024)
      pc_content = f.read(pc_len)
      hash256 = utility.get_hash256(pc_content)
      hash384 = utility.get_hash384(pc_content)
      if (bytes.fromhex(hash256) == self.cap_dict['hash256']) and \
      (bytes.fromhex(hash384) == self.cap_dict['hash384']):
        f1.write(pc_content)


def main(args):
  """ sign cpld capsule in command line
  """
  parser = argparse.ArgumentParser(description="-- sign CPLD update capsule")
  parser.add_argument('-u',   '--unsigned_capsule', metavar="[unsigned capsule]", dest= 'unsigncap', help="unsiged capsule image file")
  parser.add_argument('-rk',  '--root_private',   metavar="[root private key]", dest= 'rk_prv',  help='root private key in pem format')
  parser.add_argument('-csk', '--csk_private',    metavar="[csk private key]",  dest= 'csk_prv', help='csk private key in pem format')
  parser.add_argument('-cskid',  '--csk_id',       metavar="[csk id number]",  dest= 'csk_id', default = 0, help='csk id number 0-127, default is 0')
  parser.add_argument('-o',   '--signed_cap',     metavar="[signed capsule]",   dest= 'signedcap', default=None,
                      help='optional signed capsule file name, optional. default is cpld_update_capsule_signed.bin')
  args = parser.parse_args(args)
  print(args)

  mycpld = CPLD(args.unsigncap, args.rk_prv, args.csk_prv, args.csk_id)
  if args.signedcap == None:
    args.signedcap = 'cpld_update_capsule_signed.bin'
  mycpld.set_signed_cap(args.signedcap)
  mycpld.sign_capsule()

if __name__ == '__main__':
  main(sys.argv[1:])
