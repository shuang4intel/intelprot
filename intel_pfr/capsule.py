#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  Generate and sign various PFR capsules, so far it includes:

  * Key cancellation capsule
  * Decommission capsule
  * AFM capsule

  Generate AFM staging capsule
  *****************************

  in command line
  ===============

  Generate AFM staging capsule in command prompt::

    # generate reference manifest to your work directory
    >python -m intel_pfr.capsule -start_afm
    # modify the reference jsson file and replace your keys, then
    # generate new BMC image with active/recovery afm capsule
    >python -m intel_pfr.capsule afm -a <manifest_file> -b <bmc_image>
    # generate afm staging capsule only
    >python -m intel_pfr.capsule afm -a <manifest_file>

  in python console or script
  ===========================

  code block for generating afm staging capsule::

    >>>from intel_pfr import capsule
    >>>myafm = capsule.AFM(<afm_manifest>)
    >>>myafm.build_staging_afm()  # build AFM staging capsule

  code block for generating new BMC image with AFM capsule integrated and also include afm staging capsule::

    >>>from intel_pfr import capsule, bmc
    >>>myafm = capsule.AFM(<afm_manifest>)
    >>>myafm.build_afm()  # build AFM active, recovery and staging capsule
    >>>bmc.load_afm_capsule(<bmc_image> myafm.afm_image, myafm.afm_recovery_image)

"""
from __future__ import print_function
from __future__ import division

import os, struct, json, sys, shutil, getopt, argparse
import logging
logger = logging.getLogger(__name__)
from intel_pfr import sign, keys

_BMC_ACT_PFM   = 0x0080000
_BMC_STAGING   = 0x4A00000
_BMC_RCV_START = 0x2a00000
_PCH_STAGING   = 0x6A00000
_CPLD_STAGING  = 0x7A00000
_CPLD_RECOVERY = 0x7F00000
PAGE_SIZE      = 0x1000

DECOMM_PCTYPE  = 0x200

AFM_CAP_SIZE   = 128*1024  # 128KB total size
AFM_ALIGN_SIZE = 4*1024    # 4KB aligned for each device AFM
AFM_SIGN_SIZE  = 1024      # 1KB blocksign size
AFM_TAG  = 0x8883CE1D
AFM_TYPE = 0x3
AFM_HEAD_FMT  = "<IBBH16sI11s"
AFM_BODY  ='<HBBBHBBBHIHH20s512sIIBBH64s64sBBH64s'

dict_AFM_struct = {
'afm_tag'        : {'offset':0x000, 'length':4  },
'afm_svn'        : {'offset':0x004, 'length':1  },
'rsvd'           : {'offset':0x005, 'length':1  },
'afm_ver'        : {'offset':0x006, 'length':2  },
'oem_data'       : {'offset':0x008, 'length':16 },
'afm_header_size': {'offset':0x018, 'length':4  }
}
dict_AFM_struct_fmt = '<IBBH16sI'

dict_AFM_header = {
'afmTYPE'       : {'offset':0x000, 'length':1  },
'devAddr'       : {'offset':0x001, 'length':1  },
'devUUID'       : {'offset':0x002, 'length':2  },
'rsvd'          : {'offset':0x004, 'length':4  },
'afm_Addr'      : {'offset':0x008, 'length':4  }
}
dict_AFM_header_fmt = '<BBHII'

dict_AFM = {
'uuid'          : {'offset':0x000, 'length':2  },
'busID'         : {'offset':0x002, 'length':1  },
'deviceAddr'    : {'offset':0x003, 'length':1  },
'bind_spec'     : {'offset':0x004, 'length':1  },
'bind_spec_ver' : {'offset':0x005, 'length':2  },
'policy'        : {'offset':0x007, 'length':1  },
'svn'           : {'offset':0x008, 'length':1  },
'rsvd1'         : {'offset':0x009, 'length':1  },
'afm_ver'       : {'offset':0x00A, 'length':2  },
'curve_magic'   : {'offset':0x00C, 'length':4  },
'plt_man_str'   : {'offset':0x010, 'length':2  },
'plt_man_id'    : {'offset':0x012, 'length':2  },
'rsvd2'         : {'offset':0x014, 'length':20 },
'pub_key_xy'    : {'offset':0x028, 'length':512},
'pub_key_exp'   : {'offset':0x228, 'length':4  },
'total_mea'     : {'offset':0x22C, 'length':4  },
'num_of_mea'    : {'offset':0x230, 'length':1  },
'mea_val_type'  : {'offset':0x231, 'length':1  },
'mea_val_size'  : {'offset':0x232, 'length':2  },
'mea_0_0'       : {'offset':0x234, 'length':64 },
'mea_0_1'       : {'offset':0x274, 'length':64 },
'num_of_mea'    : {'offset':0x2B4, 'length':1  },
'mea_val_type'  : {'offset':0x2B5, 'length':1  },
'mea_val_size'  : {'offset':0x2B6, 'length':2  },
'mea_1_0'       : {'offset':0x2B8, 'length':64 }
}
dict_AFM_fmt = '<HBBBHBBBHIHH20s512sIIBBH64s64sBBH64s'


KCCC_PCTYPE = {
"cpld_cap": 0x100,
"pch_pfm" : 0x101,
"pch_cap" : 0x102,
"bmc_pfm" : 0x103,
"bmc_cap" : 0x104,
}

class Key_Cancellation(object):
  """ class of key cancellation capsule

  build and parse key cancellation certificate capsule

  :param csk_id: id of the CSK to build key cancellation certificate (0 - 127)
  :param rk_prv: root private key in PEM format, including file path
  :param fdir: target folder of key cancellation certificate, default is current work directly
  :param pctype: protect type of the CSK to be cancelled, integer or string, default is to create all five types

         integer::

           * 0x0 - PFR CPLD Update Capsule;
           * 0x1 - PFR PCH PFM;
           * 0x2 - PFR PCH Update Caosule;
           * 0x3 - PFR BMC PFM;
           * 0x4 - PFR BMC Update Capsule

        string::

          * "cpld_cap"
          * "pch_pfm"
          * "pch_cap"
          * "bmc_pfm"
          * "bmc_cap"

        if not include pctype, but specified cskid, build all 5 types of certificates

  Example:
  ::

    >>>from intel_pfr import capsule
    # build PCH PFM cancel. cert. for csk ID 2
    >>>obj1 = capsule.Key_Cancellation(csk_id=2, rk_prv=<rk_prv>, fdir=<>, pctype=1)
    >>>obj1.build()

  """
  def __init__(self, csk_id, rk_prv, fdir=None, pctype=None):
    self.csk_id  = int(csk_id, 0)
    self.rk_prv  = rk_prv
    self.pfr_ver = 3 if keys.get_curve(self.rk_prv) == 'NIST384p' else 2
    self.fdir    = fdir
    if self.fdir is None:
      self.fdir = os.getcwd()

    # set self.pctype based on integer
    try:
      pctype = int(pctype, 0)
      if isinstance(pctype, int):
        self.pctype = pctype | 0x100  # pctype = 0x0, 0x1, 0x2, 0x3, 0x4
        # search pc type string for file name use
        for k in KCCC_PCTYPE:
          if KCCC_PCTYPE[k] == self.pctype:
            self.pcstr = k
    except:
      # set self.pctype based on string and key value in KCCC_PCTYPE
      if isinstance(pctype, str):
        self.pcstr  = pctype.lower()
        self.pctype = KCCC_PCTYPE[pctype.lower()]
      if pctype is None:
        self.pctype = (0x100, 0x101, 0x102, 0x103, 0x104)
        self.pcstr  = ('capld_cap', 'pch_pfm', 'pch_cap', 'bmc_pfm', 'bmc_cap')
      pass

  def build(self):
    """ build key cancellation certificate
    """
    if isinstance(self.pctype, int):
      self.payload_file = os.path.join(self.fdir, 'kcc_%s_csk%d.bin'%(self.pcstr, self.csk_id))
      with open(self.payload_file, 'wb') as f:
        bdata = struct.pack("<I", self.csk_id) + b'\x00'*124
        f.write(bdata)
      kccc = sign.Signing_No_B1CSK(self.payload_file, self.pctype, self.csk_id, self.rk_prv)
      kccc.sign()
    else:
      for (pctype, pcstr) in zip(self.pctype, self.pcstr):
        self.payload_file = os.path.join(self.fdir, 'kcc_{}_csk{}.bin'.format(pcstr, self.csk_id))
        with open(self.payload_file, 'wb') as f:
          bdata = struct.pack("<I", self.csk_id) + b'\x00'*124
          f.write(bdata)
        sign.Signing_No_B1CSK(self.payload_file, pctype, self.csk_id, self.rk_prv).sign()


class Decommission(object):
  """ class for build and sign decommission capsule

  The Decommission reuses the same Protected Content authentication format,
  but the payload is 128 bytes of 0s. The Decommission Certificate should be used with the CPLD Update CSK.

  :param csk_id: id of the CSK to build key cancellation certificate (0 - 127)
  :param rk_prv: root private key in PEM format, including file path
  :param csk_prv: csk private key in PEM format, including file path
  :param fdir: target folder of key cancellation certificate, default is current work directly

  Example::

    >>>from intel_pfr import capsule
    # build decommission capsule with csk ID 2
    >>>obj1 = capsule.Decommission(cskid=2, rk_prv_pem=<rk_prv>, csk_prv_pem = <csk_prv>, fdir=<>)
    >>>obj1.build()

  """
  def __init__(self, csk_id, rk_prv, csk_prv, fdir=None):
    self.csk_id  = int(csk_id, 0)
    self.rk_prv  = rk_prv
    self.csk_prv = csk_prv
    self.pfr_ver = 3 if keys.get_curve(self.rk_prv) == 'NIST384p' else 2
    self.pctype  = DECOMM_PCTYPE  # Bit[9]=1, it is 512
    self.fdir    = fdir
    if self.fdir is None:
      self.fdir = os.getcwd()

  def build(self):
    """ build key cancellation certificate
    """
    self.payload_file = os.path.join(self.fdir, 'decomm_cap_cskid{:d}.bin'.format(self.csk_id))
    with open(self.payload_file, 'wb') as f:
      f.write(b'\x00'*128)
    decomm = sign.Signing(self.payload_file, self.pctype, self.csk_id, self.rk_prv, self.csk_prv)
    decomm.sign()


class AFM(object):
  """ class for AFM build

  :param manifest: JSON file with AFM manifest.json. This file should be modified from afm_manifest.json reference


  """
  def __init__(self, manifest):
    self.work_path = os.path.dirname(manifest)  # set manifest file path as work_path for afm
    with open(manifest, 'r') as f:
      self.manifest = json.load(f)
    self.afm = None
    self.lst_afm_dev = []  # list of single device afm image
    self.pc_type = 6
    self.csk_id  = 0    # default CSKID is 0
    self.pfr_ver = 3    # PFR Version 3.0 is used for signing
    self.svn   = int(self.manifest["svn"], 0)
    self.revision = int(self.manifest["revision"], 0)
    self.oem_data = bytes.fromhex(self.manifest["oem_data"])
    self.length = len(self.manifest["afm_header"])*12
    self.rk_prv = self.manifest["root_private_key"]
    self.csk_prv = self.manifest["csk_private_key"]

    self.afm_struct = os.path.join(self.work_path, "afm_struct.bin")
    self.afm_struct_signed = os.path.join(self.work_path, "afm_struct_signed.bin")
    self.afm_image_presign = os.path.join(self.work_path, "afm_capsule_presigned.bin")
    self.afm_image = os.path.join(self.work_path, "afm_active_capsule.bin")
    self.afm_recovery_image = os.path.join(self.work_path, "afm_recovery_capsule.bin")
    self.afm_staging_image  = os.path.join(self.work_path, "afm_staging_capsule.bin")

  def set_signing_keys(self, root_prv_key, csk_prv_key):
    """ set signing keys

    :param root_prv_key: root private key in PEM format
    :param csk_prv_key: CSK private key in PEM format

    """
    self.rk_prv  = root_prv_key
    self.csk_prv = csk_prv_key

  def set_csk_id(self, cskID):
    self.csk_id = cskID


  def build_afm_single_device(self, dict_input):
    """ build AFM for single device

    :param dict_input: dictionary variable of input.
       This is an internal function

    """
    fname = "afm_dev_"+dict_input['index']+'.bin'
    self.unsigned_afm_image = os.path.join(self.work_path, fname)

    uuid     = struct.pack("<H", int(dict_input['uuid'], 0))
    busid    = struct.pack("B", int(dict_input['busid'], 0))
    dev_addr = struct.pack("B", int(dict_input['device_addr'], 0))
    binding_spec = struct.pack("B", int(dict_input['binding_spec'], 0))
    binding_spec_ver = struct.pack("<H", int(dict_input['binding_spec_version'], 0))
    policy = struct.pack("B", int(dict_input['policy'], 0))
    svn    = struct.pack("B", int(dict_input['svn'], 0))
    rsvd1  = b'\xff'
    afm_version  = struct.pack("<H", int(dict_input['afm_version'], 0))
    pubkey_curve = struct.pack("<I", int(dict_input['public_key_curve_magic'], 0))
    manuf_str    = struct.pack("<H", int(dict_input['manufacture_string'], 0))
    manuf_model  = struct.pack("<H", int(dict_input['manufacture_model'], 0))
    rsvd2 = b'\xff'*20
    pub_key_x = bytes.fromhex(dict_input['public_key_X'])
    pub_key_y = bytes.fromhex(dict_input['public_key_Y'])
    pub_key_exp = struct.pack("<I", int(dict_input['public_key_exponent'], 0))
    total_meas = struct.pack("<I", int(dict_input['number_of_measurement'], 0))
    afm_dev_part1 = uuid + busid + dev_addr + binding_spec + binding_spec_ver + \
                    policy + svn + rsvd1 + afm_version + pubkey_curve + \
                    manuf_str + manuf_model + rsvd2 + \
                    pub_key_x + pub_key_y + bytes(512-96) + pub_key_exp + total_meas

    # process measurements
    total_index = int(dict_input['number_of_measurement'], 0)
    lst_dev_meas = dict_input['measurement']
    afm_dev_part2 = b''
    for d in lst_dev_meas:
      num_of_meas = int(d["number_of_possible_measurement"], 0)
      afm_dev_part2 += struct.pack("B", int(d["number_of_possible_measurement"], 0))
      afm_dev_part2 += struct.pack("B", int(d["value_type"], 0))
      afm_dev_part2 += struct.pack("<H", int(d["size"], 0))
      pad_bytes = b''
      if int(d["size"], 0)%4 != 0:
        pad_bytes = bytes(4 - int(d["size"], 0)%4)
      for i in range(0, num_of_meas):
        assert(len(d["measurement"][i]) >= 1)  # not allow empty array of measurement in json
        if len(d["measurement"][i]) == 1:
          d["measurement"][i] = d["measurement"][i]
        elif len(d["measurement"][i]) > 1:
          print("-- {}".format(d["measurement"][i]))
          temp = ''.join(d["measurement"][i])
          d["measurement"][i] = temp

        afm_dev_part2 += bytes.fromhex(d["measurement"][i])+pad_bytes

    padsize= AFM_ALIGN_SIZE - AFM_SIGN_SIZE - len(afm_dev_part1 + afm_dev_part2)  # pad 0xff to 3K (add 1K blocksign) as 4K alignment
    with open(self.unsigned_afm_image, 'wb') as f:
      f.write(afm_dev_part1)
      f.write(afm_dev_part2)
      f.write(b'\xff'*padsize)

    # append unsigned single device afm image file name to self.lst_afm_dev
    print("append unsigned afm image---{}".format(self.unsigned_afm_image))
    self.lst_afm_dev.append(self.unsigned_afm_image)

  def sign_afm_device(self):
    """ signing single device AFM using two private keys """
    self.lst_signed_afm_dev = []
    for fname in self.lst_afm_dev:
      x = sign.Signing(fname, self.pc_type, self.csk_id, self.rk_prv, self.csk_prv)
      fname_signed = os.path.splitext(fname)[0]+"_signed.bin"
      x.set_signed_image(fname_signed)
      x.sign()
      self.lst_signed_afm_dev.append(fname_signed)
      os.remove(fname)

  def build_afm_struct(self):
    """ build AFM structure """
    afm_hd  = struct.pack("<IBBH", AFM_TAG, self.svn, 0xff, self.revision)
    afm_hd += self.oem_data
    afm_hd += struct.pack("<I", self.length)

    # loop all afm header/address definition
    afm_body = b''
    for afmhd in self.manifest['afm_header']:
      spi_type = 0x3
      smb_addr = int(afmhd['smbus_address'], 0)
      dev_uuid = int(afmhd['uuid'], 0)
      afm_addr = int(afmhd['afm_address'], 0)
      length   = 0x1000  # length of afm
      afm_body += struct.pack("<BBHII", spi_type, smb_addr, dev_uuid, length, afm_addr)

    afm_padding = bytes(b'\xff'*(AFM_ALIGN_SIZE - AFM_SIGN_SIZE -len(afm_hd + afm_body)))  #1024 is 1K block sign size
    with open(self.afm_struct, 'wb') as f:
      f.write(afm_hd)
      f.write(afm_body)
      f.write(afm_padding)

    # sign afm_structure_header
    x = sign.Signing(self.afm_struct, self.pc_type, self.csk_id, self.rk_prv, self.csk_prv)
    x.set_signed_image(self.afm_struct_signed)
    x.sign()
    os.remove(self.afm_struct)

  def build_afm(self):
    """ build afm capsule """

    self.build_afm_struct()

    for d in self.manifest['devices']:
      self.build_afm_single_device(d)
    self.sign_afm_device()

    with open(self.afm_image, 'wb') as f:
      with open(self.afm_struct_signed, 'rb') as f1:
        f.write(f1.read())
      for signed_dev_afm in self.lst_signed_afm_dev:
        with open(signed_dev_afm, 'rb') as fdev:
           f.write(fdev.read())
      # padd total to 128KB
      f.seek(0,2)
      f.write(b'\xff'*(AFM_CAP_SIZE - f.tell()))

    with open(self.afm_image_presign, 'wb') as f1, open(self.afm_image, 'rb') as f2:
      f1.write(f2.read(127*1024))

    # create afm recovery/staging capsule
    rec = sign.Signing(self.afm_image_presign, self.pc_type, self.csk_id, self.rk_prv, self.csk_prv)
    rec.set_signed_image(self.afm_recovery_image)
    rec.sign()

    stg = sign.Signing(self.afm_image_presign, self.pc_type, self.csk_id, self.rk_prv, self.csk_prv)
    stg.set_signed_image(self.afm_staging_image)
    stg.sign()

    # clean immediate files:
    #os.remove(self.afm_struct)
    os.remove(self.afm_struct_signed)
    os.remove(self.afm_image_presign)
    for i in self.lst_signed_afm_dev:
      os.remove(i)

    print("**** Done -- build afm capsule! ***")

  def build_staging_afm(self):
    """ build AFM staging capsule """

    self.build_afm_struct()
    for d in self.manifest['devices']:
      self.build_afm_single_device(d)
    self.sign_afm_device()

    with open(self.afm_image_presign, 'wb') as f:
      with open(self.afm_struct_signed, 'rb') as f1:
        f.write(f1.read())
      for signed_dev_afm in self.lst_signed_afm_dev:
        with open(signed_dev_afm, 'rb') as fdev:
           f.write(fdev.read())
      # padd total to 127KB
      f.seek(0,2)
      print('pad_ff_size: 0x{:x}, f.tell() = 0x{:x}'.format((AFM_CAP_SIZE -AFM_SIGN_SIZE - f.tell()), f.tell()))
      f.write(b'\xff'*(AFM_CAP_SIZE -AFM_SIGN_SIZE - f.tell()))

    stg = sign.Signing(self.afm_image_presign, self.pc_type, self.csk_id, self.rk_prv, self.csk_prv)
    stg.set_signed_image(self.afm_staging_image)
    stg.sign()

    # clean immediate files:
    os.remove(self.afm_struct_signed)
    os.remove(self.afm_image_presign)
    for i in self.lst_signed_afm_dev:
      os.remove(i)


def main(args):
  """ command line execution inteface

  Execution command in command prompt::

    # Create AFM capsule
    >python -m intel_pfr.capsule -start_afm
    >python -m intel_pfr.capsule -afm -a <afm_manifest_json> -b <BMC image>

    # create decommission capsule
    >python -m intel_pfr.capsule -decomm -rk <root private key> -csk <csk private key> -id <CSK ID>

    # create key cancellation cerificate
    >python -m intel_pfr.capsule -kcc -rk <root private key> -id <CSK ID> -type <Protect Content type>


  """

  parser = argparse.ArgumentParser(description='build capsule from manifest json file.')
  parser.add_argument('-start_afm', action='store_true', help='start AFM: generate manifest reference file')
  parser.add_argument('-r', '--reference', metavar="[reference platform]", dest='reference', help='reference design name: eaglestream, whitley, idaville.')

  subparser = parser.add_subparsers(dest='capsule')
  afmcap = subparser.add_parser('afm')
  afmcap.add_argument('-a', '--afm_manifest',  metavar="[AFM manifest]",  dest='afm_m', help='afm manifest json file')
  afmcap.add_argument('-b', '--bmc_image',  metavar="[bmc_image]",  dest='bmc_image', help='bmc pfr image to add afm')

  decomm = subparser.add_parser('decomm')
  decomm.add_argument('-rk',  '--root_prv', metavar="[root private key]", dest='rk_prv',  help='Root Private Key in PEM format')
  decomm.add_argument('-csk', '--csk_prv',  metavar="[CSK private key]",  dest='csk_prv', help='CSK Private Key in PEM format')
  decomm.add_argument('-id',  '--csk_id',   metavar="[CSK ID number]",    dest='csk_id', help='CSK ID number')

  kcccap = subparser.add_parser('kcc')
  kcccap.add_argument('-rk', '--root_prv',  metavar="[root private key]",  dest='rk_prv', help='root private key (PEM format) for key cancellation certificate')
  kcccap.add_argument('-id', '--cskid',     metavar="[CSK ID to be cancelled]",  dest='csk_id', help='CSK ID to be cancelled')
  kcccap.add_argument('-type', '--pctype',  metavar="[PC Type]",  dest='pc_type', help='PC Type for Key Cancellation Certificate, build all types of KCC if no input')

  args = parser.parse_args(args)
  #print(args.capsule)
  if args.start_afm:
    print("-- generated afm_manifest.json reference file")
    src_json_file = os.path.join(os.path.dirname(__file__), 'json', 'afm_manifest.json')
    dst_json_file = os.path.join(os.getcwd(), 'afm_manifest.json')
    shutil.copyfile(src_json_file, dst_json_file)
    lst_keys = ('key_root_prv.pem', 'key_csk_prv.pem')
    for f in lst_keys:
      src_f = os.path.join(os.path.dirname(__file__), 'keys', 'eaglestream', f)
      dst_f = os.path.join(os.getcwd(), f)
      shutil.copyfile(src_f, dst_f)

  if args.capsule == 'afm':
    if (args.afm_m != None) and (args.bmc_image == None):
      print("-- build afm staging capsule only" )
      myafm=AFM(args.afm_m)
      myafm.build_afm()

    if (args.afm_m != None) and (args.bmc_image != None):
      print("-- build new BMC image with afm integrated and also build afm staging capsule" )
      myafm=AFM(args.afm_m)
      myafm.build_afm()
      from intel_pfr import bmc
      bmc.load_afm_capsule(args.bmc_image, myafm.afm_image, myafm.afm_recovery_image)

    #print(args)
  if args.capsule == 'decomm':
    print(args)
    obj1 = Decommission(csk_id=args.csk_id, rk_prv=args.rk_prv, csk_prv=args.csk_prv, fdir=None)
    obj1.build()

  if args.capsule == 'kcc':
    print(args)
    obj1 = Key_Cancellation(csk_id=args.csk_id, rk_prv=args.rk_prv, fdir=None, pctype=args.pc_type)
    obj1.build()

if __name__ == '__main__':
  main(sys.argv[1:])
