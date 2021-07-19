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
import os, sys, shutil, argparse, pathlib
from intel_pfr import sign

_CPLD_CAP_PCTYPE  = 0   # pc_type for CPLD update capsule

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
