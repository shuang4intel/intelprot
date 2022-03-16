#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  Generate and sign various PFR capsules, so far it includes:

  * Key cancellation capsule
  * Decommission capsule
  * AFM capsule
  * CFM capsule

  Command line
  *****************************

  help-menu::

    >python -m intelprot.capsule -h
    >python -m intelprot.capsule <sub-cmd> -h # sub-cmd example: {afm,decomm,kcc,stgcap,cfm}

  Generate AFM staging capsule
  *****************************

  in command line
  ===============

  Generate AFM staging capsule in command prompt::

    # generate reference manifest to your work directory
    >python -m intelprot.capsule -start_afm
    # modify the reference json file and replace your keys, then
    # generate new BMC image with active/recovery afm capsule
    >python -m intelprot.capsule afm -a <manifest_file> -b <bmc_image>
    # generate afm staging capsule only
    >python -m intelprot.capsule afm -a <manifest_file>

  in python console or script
  ===========================

  code block for generating afm staging capsule::

    >>>from intelprot import capsule
    >>>myafm = capsule.AFM(<afm_manifest>)
    >>>myafm.build_staging_afm()  # build AFM staging capsule

  code block for generating new BMC image with AFM capsule integrated and also include afm staging capsule::

    >>>from intelprot import capsule, bmc
    >>>myafm = capsule.AFM(<afm_manifest>)
    >>>myafm.build_afm()  # build AFM active, recovery and staging capsule
    >>>bmc.load_afm_capsule(<bmc_image> myafm.afm_image, myafm.afm_recovery_image)

  Generate CFM staging capsule
  *****************************

  command prompt
  ===============

  Generate CFM staging capsule in command prompt::

    # generate reference manifest to your work directory
    >python -m intelprot.capsule -start_cfm
    # modify the reference json file and replace your keys, then
    >python -m intelprot.capsule cfm -c <cfm_manifest_file>

"""
from __future__ import print_function
from __future__ import division

import os, struct, json, sys, shutil, getopt, argparse
from collections import OrderedDict
import logging, math
logger = logging.getLogger(__name__)
from intelprot import sign, keys, utility, pfm, bmc, ifwi

_BMC_ACT_PFM   = 0x0080000
_BMC_STAGING   = 0x4A00000
_BMC_RCV_START = 0x2A00000
_PCH_STAGING   = 0x6A00000
_CPLD_STAGING  = 0x7A00000
_CPLD_RECOVERY = 0x7F00000
PAGE_SIZE      = 0x1000
BLOCK_SIGN_SIZE= 0x400
DECOMM_PCTYPE  = 0x200
BLK0_MAGIC_TAG = 0xB6EAFD19

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

    >>>from intelprot import capsule
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

    >>>from intelprot import capsule
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


PBC_STRUCT_KEY = ('pbc_tag', 'pbc_ver', 'page_size', 'pattern_size', 'pattern', 'bmap_size', \
'payload_len', 'pbc_rsvd', 'active_bmap', 'compress_bmap')
PBC_TAG = 0x5F504243
PFM_TAG = 0x02B3CE1D
PAGE_SIZE = 0x1000

class BMC_Capsule(object):
  """ class for BMC update capsule operations, including::

    * checking PFM inside capsule
    * decompression capsule to recover it as a BMC pfr image, based on the manifest JSON file

   In the decompressed image, the recovery capsule is included, staging area is empty
   The signed pfm in the capsule is used.

  :param cap_image: BMC update capsule image file, either unsigned or signed capsule. Signed capsule will be added in flash recovery area.
  :param manifest_json: file name of the manifest jason file used to build pfr bmc image and the capsule.
                        It is required to follow the format.

  """
  def __init__(self, cap_image, manifest_json):
    self.cap_image = cap_image
    with open(manifest_json, 'r') as f:
      self.manifest=json.load(f)

    self.csk_prv = os.path.join(os.path.dirname(manifest_json), self.manifest['build_image']['csk_private_key'])
    self.rk_prv  = os.path.join(os.path.dirname(manifest_json), self.manifest['build_image']['root_private_key'])
    self.dict_spi_parts = self.manifest['image-parts']
    self.pfr_bmc_image_size = 0
    for d in self.dict_spi_parts:
      d['offset'] = int(d['offset'], 16)
      d['size'] = int(d['size'], 16)
      if d['name'] == 'pfm':
        self.pfm_offset = d['offset']
        self.pfm_size = d['size']
      if d['name'] == 'rc-image':
        self.rcv_offset = d['offset']
        self.rcv_size = d['size']
      if d['offset'] > self.pfr_bmc_image_size:
        self.pfr_bmc_image_size = d['offset'] + d['size']

    self.out_image = os.path.join(os.path.dirname(self.cap_image), os.path.splitext(cap_image)[0]+'_decomp.bin')
    self.deComp_dict = pfm.ConfigDict()
    self.pbc_st_addr = int(utility.bin_search_tag(self.cap_image, PBC_TAG)[0], 0)
    self.pfm_st_addr = int(utility.bin_search_tag(self.cap_image, pfm.PFM_MAGIC)[0], 0)
    self.cap_pfm = pfm.PFM(self.cap_image)
    self.pfm_len = self.cap_pfm.pfm_dict['length']
    if self.pfm_st_addr < BLOCK_SIGN_SIZE:
      logger.error("Error: pfm_st_addr should be bigger than 0x400")

    with open(self.cap_image, 'rb') as f:
      lst_temp = struct.unpack('<III', f.read(12))
      blk0_tag, blk0_pctype = lst_temp[0], lst_temp[2]
      if (blk0_tag == BLK0_MAGIC_TAG) and (blk0_pctype == bmc._PCTYPE_BMC_PFM) and (self.pfm_st_addr == BLOCK_SIGN_SIZE):
        self.if_signed_cap = False
      if (blk0_tag == BLK0_MAGIC_TAG) and (blk0_pctype == bmc._PCTYPE_BMC_CAP) and (self.pfm_st_addr == 2*BLOCK_SIGN_SIZE):
        self.if_signed_cap = True

      f.seek(self.pfm_st_addr - BLOCK_SIGN_SIZE)  # seek to blocksign start offset
      self.signed_pfm_bdata = f.read(BLOCK_SIGN_SIZE + self.pfm_len) # read signed pfm in capsule

    N = int(self.pfr_bmc_image_size/(PAGE_SIZE*8))
    PBC_STRUCT_FMT = "<IIIIIII100s{}s{}s".format(N, N)
    self.pbc_head_size = struct.calcsize(PBC_STRUCT_FMT)
    with open(self.cap_image, 'rb') as f:
      f.seek(self.pbc_st_addr)
      lst_temp = struct.unpack(PBC_STRUCT_FMT, f.read(self.pbc_head_size))

    for (k, v) in zip(PBC_STRUCT_KEY, lst_temp):
      self.deComp_dict[k] = v

    self.payload_len = self.deComp_dict['payload_len']
    self.erase_bmap  = self.deComp_dict['active_bmap']
    self.copy_bmap   = self.deComp_dict['compress_bmap']
    self.payload_staddr= self.pbc_st_addr + self.pbc_head_size


  def show(self):
    """display deComp_dict """
    for k in self.deComp_dict:
      if isinstance(self.deComp_dict[k], int):
        print(k, ' = ', hex(self.deComp_dict[k]))
      #if isinstance(self.deComp_dict[k], (bytes, bytearray)):
      #  print(k, ' = ', self.deComp_dict[k].hex())
    #print(hex(self.pfm_offset), hex(self.rcv_offset))
    logger.info('pfm_offset: 0x{:x}, rcv_offset: 0x{:x}'.format(self.pfm_offset, self.rcv_offset))


  def decompression(self):
    """ get decompressed image """
    with open(self.cap_image, 'rb') as f:
      f.seek(self.payload_staddr)
      self.payload_bdata = f.read(self.payload_len)

    # copy data to output image based on erase and copy bitmap
    start_addr, end_addr = 0, self.pfr_bmc_image_size
    end_page = end_addr >> 12
    page = 0
    with open(self.out_image, 'wb+') as fout:
      addr = 0
      copy_idx = 0
      while (addr <= (end_addr-0x1000)):
        page = addr >> 12
        page_copy = (self.copy_bmap[page >> 3] & (1 << ( 7 - page%8))) >> (( 7 - page%8))
        #if page < 130:
        #  print('page = %i, copy_bmap = 0x%02x, bmapByte=%i, page_copy=%i'%(page, self.copy_bmap[page >> 3], page>>3, page_copy))
        if page_copy == 1:
          fout.write(self.payload_bdata[copy_idx*0x1000:(copy_idx+1)*0x1000])
          copy_idx += 1
        else:
          fout.write(b'\xff'*PAGE_SIZE)
        addr += PAGE_SIZE
    print('copy_idx = 0x%08x'%copy_idx)
    # add PFM
    with open(self.out_image, 'r+b') as fout:
      fout.seek(self.pfm_offset)
      fout.write(self.signed_pfm_bdata)
    # add signed recovery capsule
    if not self.if_signed_cap:
      scap = sign.Signing(self.cap_image, bmc._PCTYPE_BMC_CAP,  int(self.manifest['build_image']['csk_id'], 0), self.rk_prv, self.csk_prv)
      scap.set_signed_image("temp_bmc_signed_cap.bin")
      scap.sign()
      add_rcv_cap = 'temp_bmc_signed_cap.bin'
    if self.if_signed_cap:
      add_rcv_cap = self.cap_image
    with open(self.out_image, 'r+b') as fout, open(add_rcv_cap, 'rb') as f:
      fout.seek(self.rcv_offset)
      fout.write(f.read())


class IFWI_Capsule():
  """ class for IFWI capsule operation including capsule decompression

  """
  def __init__(self, cap_image):
    self.cap_image = cap_image
    self.out_image = os.path.join(os.path.dirname(self.cap_image), os.path.splitext(cap_image)[0]+'_decomp.bin')
    self.deComp_dict = pfm.ConfigDict()
    self.pfm_st_addr = int(utility.bin_search_tag(self.cap_image, PFM_TAG)[0], 0)
    self.pbc_st_addr = int(utility.bin_search_tag(self.cap_image, PBC_TAG)[0], 0)

    self.pfr_ifwi_image_size = 64*1024*1024
    N = int(self.pfr_ifwi_image_size/(PAGE_SIZE*8))
    PBC_STRUCT_FMT = "<IIIIIII100s{}s{}s".format(N, N)
    self.pbc_head_size = struct.calcsize(PBC_STRUCT_FMT)
    with open(self.cap_image, 'rb') as f:
      f.seek(self.pbc_st_addr)
      lst_temp = struct.unpack(PBC_STRUCT_FMT, f.read(self.pbc_head_size))

    for (k, v) in zip(PBC_STRUCT_KEY, lst_temp):
      self.deComp_dict[k] = v

    self.payload_len = self.deComp_dict['payload_len']
    self.erase_bmap  = self.deComp_dict['active_bmap']
    self.copy_bmap   = self.deComp_dict['compress_bmap']
    self.payload_staddr= self.pbc_st_addr + self.pbc_head_size
    self.prov = ifwi.Agent(self.cap_image)
    self.prov.get_pfrs_value()
    self.pfm_offset = int(self.prov._pfrs['pch_active'], 0)
    self.rcv_offset = int(self.prov._pfrs['pch_recovery'], 0)

  def decompression(self):
    """ get decompressed image
    """
    with open(self.cap_image, 'rb') as f:
      f.seek(self.payload_staddr)
      self.payload_bdata = f.read()
    #print('payload_bdata size:', len(self.payload_bdata))
    # copy data to output image based on erase and copy bitmap
    start_addr, end_addr = 0, self.pfr_ifwi_image_size
    end_page = end_addr >> 12 # one page is 4KB (0x4000), shift 12 bit
    page = 0
    with open(self.out_image, 'wb+') as fout:
      addr = 0
      copy_idx = 0
      while (addr <= (end_addr-PAGE_SIZE)):
        page = addr >> 12
        page_copy = (self.copy_bmap[page >> 3] & (1 << ( 7 - page%8))) >> (( 7 - page%8))
        #if page < 130:
        #  print('page = %i, copy_bmap = 0x%02x, bmapByte=%i, page_copy=%i'%(page, self.copy_bmap[page >> 3], page>>3, page_copy))
        if page_copy == 1:
          fout.write(self.payload_bdata[copy_idx*PAGE_SIZE:(copy_idx+1)*PAGE_SIZE])
          copy_idx += 1
        else:
          fout.write(b'\xff'*PAGE_SIZE)
        addr += PAGE_SIZE
    print('copy_idx = 0x%08x'%copy_idx)
    # add PFM area and recovery area
    with open(self.out_image, 'r+b') as f1, open(self.cap_image, 'rb') as f2:
      f2.seek(self.pfm_st_addr - BLOCK_SIGN_SIZE)
      self.signed_pfm_bdata = f2.read(self.pbc_st_addr - (self.pfm_st_addr - BLOCK_SIGN_SIZE))
      f1.seek(self.pfm_offset)
      f1.write(self.signed_pfm_bdata)
      # add cap_image to recovery capsule area
      f1.seek(self.rcv_offset)
      f2.seek(0)
      f1.write(f2.read())

  def show_pfm(self):
    """ display PFM inside the capsule """
    pfmobj = pfm.PFM(self.cap_image)
    pfmobj.show()

  def show(self):
    """ show capsule information """
    logger.info('-- capsule image :{}'.format(self.cap_image))
    logger.info('-- PFM offset : 0x{:08x}'.format(self.pfm_offset))
    logger.info('-- RCV offset : 0x{:08x}'.format(self.rcv_offset))
    self.show_pfm()

# for nested dictionary
class ConfigDict(OrderedDict):
  """ define an ordered dictionary """
  def __missing__(self, key):
    val = self[key] = ConfigDict()
    return val

PBC_TAG = 0x5F504243
PFM_HEAD_FMT, PFM_HEAD_KEY = '<IBBHI16sI', ('tag', 'svn', 'bkc_ver', 'pfm_rev', 'rsvd1', 'oem_data', 'pfm_size')

class STG_Capsule(object):
  """ class to process/update a valid good recovery and staging capsule following Intel PFR data structure
  This is generic class for updating BMC, IFWI, and CPLD recovery/staging capsule for PFR validation

  Input: a known good validated signed capsule
  Output: an updated signed capsule with updated parameters including csk_id, svn, etc.

  :param cap_image: known good update capsule from BKC or customer built capsule. It can be bmc, ifwi, or cpld capsule.
  :param rk_prv: root private key in PEM format, including file path
  :param csk_prv: csk private key in PEM format, including file path
  :param csk_id: id of the CSK to build key cancellation certificate (0 - 127)
  :param svn: SVN number for the PFM inside a capsule
  :param bkc_ver: BKC Version number (one byte)
  :param pfm_rev: PFM revision (two bytes)
  :param oem_data: OEM specific data (16 bytes)

  """
  def __init__(self, cap_image, rk_prv, csk_prv, csk_id, svn=None, bkc_ver=None, pfm_rev=None, oem_data=None):
    self.new_param = ConfigDict()  # empty dictionary for new param
    self.cur_param = ConfigDict()  # empty dictionary for current param
    self.cur_param['cap_image'] = cap_image
    self.new_param['cap_image'] = os.path.splitext(cap_image)[0]+'_cskid_%d.bin'%csk_id
    self.get_length_location()
    self.deassemble()
    self.new_param['rk_prv']    = rk_prv
    self.new_param['csk_prv']   = csk_prv
    self.new_param['csk_id']    = csk_id
    self.new_param['svn']       = svn if svn else self.cur_param['svn']
    self.new_param['bkc_ver']   = bkc_ver if bkc_ver else self.cur_param['bkc_ver']
    self.new_param['pfm_rev']   = pfm_rev if pfm_rev else self.cur_param['pfm_rev']
    self.new_param['oem_data']  = oem_data if oem_data else self.cur_param['oem_data']

  def get_length_location(self):
    """ search and find protect length for PFM and capsule """

    with open(self.cur_param['cap_image'], 'rb') as f:
      cap_sigblk=f.read(0x400)
      pfm_sigblk=f.read(0x400)
      cap_len=struct.unpack("<I",  cap_sigblk[4:8])[0]
      cap_type=struct.unpack("<I", cap_sigblk[8:12])[0]
      curv_magic = struct.unpack("<I", cap_sigblk[148:152])[0]
      pfm_len=struct.unpack("<I", pfm_sigblk[4:8])[0]
      pfm_type=struct.unpack("<I", pfm_sigblk[8:12])[0]
      print("--cap_length:0x{:x}, pfm_len:0x{:x}".format(cap_len, pfm_len))

      self.cap_len, self.pfm_len, self.cap_type, self.curv_magic = cap_len, pfm_len, cap_type, curv_magic
      self.pfm_type = pfm_type
      if self.cap_type == 0x0: print("cpld capsule, pfm_type:{}".format(self.pfm_type))
      if self.cap_type == 0x2: print("ifwi capsule, pfm_type:{}".format(self.pfm_type))
      if self.cap_type == 0x4: print("bmc capsule, pfm_type:{}".format(self.pfm_type))
      if curv_magic == 0xC7B88C74: self.pfr_ver = 2
      if curv_magic == 0x08F07B47: self.pfr_ver = 3
      self.cur_param['csk_id'] = struct.unpack("<I", cap_sigblk[120:124])[0]

      logger.info("-- cap_length:0x{:x}, pfm_len:0x{:x}, pfr_ver:{}".format(self.cap_len, self.pfm_len, self.pfr_ver))
      print("-- current csk_id:{}".format(self.cur_param['csk_id']))

    if self.cap_type not in [0, 2, 4]:
      print("-- Error: it is not valid capsule, or not signed bmc, ifwi, cpld capsule !")


  def deassemble(self):
    """ deassemble a signed update capsule

    ..compress and signed format::

      Capsule_Signature(B0+B1) + {PFM_signature(B0+B1)+ {PFM} + Compression_Header + Compressed_Data}
      1024B: [B0 (128B)] + [B1_Head (16B) + B1_Root (132B) + B1_CSK(232B) + B1_B0 (104B) + B1_Pad(412B)]

    """
    with open(self.cur_param['cap_image'], 'rb') as f:
      f.seek(0x800)
      self.pfm_head = f.read(32)
      self.pfm_body = f.read(self.pfm_len - 32)
      self.cap_body = f.read(self.cap_len-0x400-self.pfm_len)
      lst_temp = struct.unpack(PFM_HEAD_FMT, self.pfm_head)
      for (k, v) in zip(PFM_HEAD_KEY, lst_temp):
        self.cur_param[k] = v

  def build_cap(self):
    """ build new capsule and sign it with new parameters """
    bdata  = struct.pack("<I", pfm.PFM_MAGIC)
    #print(self.new_param['svn'])
    #[print(self.new_param[k]) for k in self.new_param]
    bdata += struct.pack("<BBHI16sI", self.new_param['svn'], self.new_param['bkc_ver'], self.new_param['pfm_rev'], 0xffffffff, \
        self.new_param['oem_data'], self.cur_param['pfm_size'])

    with open('unsigned_pfm.bin', 'wb') as f:
      f.write(bdata)
      f.write(self.pfm_body)

    pfmcap=sign.Signing('unsigned_pfm.bin', self.pfm_type, self.new_param['csk_id'], self.new_param['rk_prv'], self.new_param['csk_prv'])
    pfmcap.set_signed_image('signed_pfm.bin')
    pfmcap.sign()

    with open('unsigned_cap.bin', 'wb') as f, open('signed_pfm.bin', 'rb') as f1:
      f.write(f1.read())
      f.write(self.cap_body)

    updcap=sign.Signing('unsigned_cap.bin', self.cap_type, self.new_param['csk_id'], self.new_param['rk_prv'], self.new_param['csk_prv'])
    updcap.set_signed_image(self.new_param['cap_image'])
    updcap.sign()


BLOCK0_FMT   = '<IIII32s48s32s'
BLOCK_SIZE   = 1024
PCLEN_OFFSET = 0x4
CSKID_OFFSET = 0x120

class CPLD_Capsule(object):
  """ take BKC cpld update capsule and signed it with customer private keys and desired CSKID
   No PFM inside cpld update capsule
  """
  def __init__(self, cpld_capsule, rk_prv, csk_prv, csk_id=None, out_capsule=None):
    self.org_cpld_capsule = cpld_capsule
    self.out_cap = out_capsule
    self.rk_prv, self.csk_prv = rk_prv, csk_prv
    with open(self.org_cpld_capsule, 'rb') as f:
      f.seek(PCLEN_OFFSET)
      self.pc_len  = struct.unpack('<I', f.read(4))[0]
      self.pc_type = struct.unpack('<I', f.read(4))[0]
      f.seek(CSKID_OFFSET)
      org_cskid = struct.unpack('<I', f.read(4))[0]
      f.seek(BLOCK_SIZE)

    # assign new csk_id if defined, else use original cskid
    self.csk_id = csk_id if csk_id else org_cskid
    print("PC_Length: 0x{:08x}, orginal csk_id = 0x{:x}, new csk_id= 0x{:x}".format(self.pc_len, org_cskid, self.csk_id))

  def get_cap_content(self):
    """ get protect content """
    with open(self.org_cpld_capsule, 'rb') as f:
      f.seek(BLOCK_SIZE)
      self.content = f.read()

  def build_cpld_capsule(self):
    """ build new signed cpld capsule """
    self.get_cap_content()
    with open('cpld_cap_content.bin', 'wb') as f:
      f.write(self.content)

    cpldcap=sign.Signing('cpld_cap_content.bin', self.pc_type, self.csk_id, self.rk_prv, self.csk_prv)
    cpldcap.set_signed_image(self.out_cap)
    cpldcap.sign()


# definition for CPLD FW capsule
CFM_ALIGN_SIZE = 4*1024    # 4KB aligned for each device CFM
CFM_PC_TYPE = 0x07         # CPLD online update (CPU/SCM/Debug CPLD) protect type

class CFM(object):
  """ Class for CPLD firmware manifest capsule operation

     CPLD Firmware Manifest data structure (CFM)
  """
  def __init__(self, manifest):
    """ constructor """
    with open(manifest, 'r') as f:
      self.manifest=json.load(f)
    self.csk_id = int(self.manifest['csk_id'], 0)
    self.rk_prv = self.manifest['root_private_key']
    self.csk_prv = self.manifest['csk_private_key']
    self.lst_cpld = [x.strip() for x in self.manifest['pfm_struct']['lst_cpld'].split(",")]

  def build_pfm_struct(self):
    """ build pfm_struct binary data """
    dic = self.manifest['pfm_struct']
    lst_key = ['pfm_tag', 'pfm_svn', 'bkc_ver', 'pfm_rev', 'dev_id', 'pfm_rsvd']
    lst = [int(dic[k], 16) for k in lst_key]
    self.pfm_head = struct.pack('<IBBHHH16s', *lst, bytes.fromhex(dic["oem_data"].strip('0x')))
    self.calc_pfm_body()

  def calc_pfm_body(self):
    """ calculate pfm body addr definition manifest """
    SPI_ADDR_TAG = 0x3
    BLOCK_SIZE, HEADER_SIZE = 1024, 4
    self.pfm_body = b''
    self.capsule_start = 0 #--use the offset address relative to 0x07c00000
    prev_start = self.capsule_start + CFM_ALIGN_SIZE
    #cpld_len = 0
    for k in self.lst_cpld:
      cpld_start = prev_start
      #print("cpld:{:20s}, cpld_len:0x{:08x}".format(k, cpld_len))
      cpld_len   = BLOCK_SIZE + HEADER_SIZE + os.path.getsize(self.manifest[k]['image_name'])
      lst = [SPI_ADDR_TAG, int(self.manifest[k]['cpld_type'], 16), 0xff, cpld_len, cpld_start]
      self.pfm_body += struct.pack('<BHBII', *lst)
      print("cpld:{:20s}, cpld_len: 0x{:08x}, prev_start: 0x{:08x}, start_addr:0x{:08x}".format(k, cpld_len, prev_start, cpld_start))
      prev_start  = cpld_start + math.ceil(cpld_len/CFM_ALIGN_SIZE)*CFM_ALIGN_SIZE
    #'{03 0000 ff 28251600 0010c007} {03 0100 ff 38d50800 0040d607} {03 0200 ff 10150c00 0020df07}'

  def build_pfm(self):
    """ build and sign pfm capsule """
    self.build_pfm_struct()
    self.pfm_len = 32+len(self.pfm_body)
    self.pfm_padsize = math.ceil(self.pfm_len/CFM_ALIGN_SIZE)*CFM_ALIGN_SIZE - self.pfm_len - 2*BLOCK_SIGN_SIZE
    with open('cfm_pfm_unsigned.bin', 'wb') as f:
      f.write(self.pfm_head + struct.pack('<I', self.pfm_len)+self.pfm_body + b'\xff'*self.pfm_padsize)

    pfmcap=sign.Signing('cfm_pfm_unsigned.bin', CFM_PC_TYPE, self.csk_id, self.rk_prv, self.csk_prv)
    pfmcap.set_signed_image('cfm_pfm_signed.bin')
    pfmcap.sign()


  def build_single_capsule(self, cpld_key):
    """ build and sign single capsule
    """
    d = self.manifest[cpld_key]
    lst_key = ['cpld_tag', 'cpld_svn', 'cpld_rsvd1', 'cpld_rev', 'cpld_rsvd2', 'cpld_type']
    lst = [int(d[k], 16) for k in lst_key]
    image_len = os.path.getsize(d['image_name'])
    capsule_head = struct.pack('<IBBHHH16sI', *lst, bytes.fromhex(d["oem_data"].strip('0x')), image_len)
    capsule_padsize = math.ceil((len(capsule_head)+image_len)/CFM_ALIGN_SIZE)*CFM_ALIGN_SIZE - (len(capsule_head)+image_len) - BLOCK_SIGN_SIZE
    capsule_unsigned = os.path.splitext(d['image_name'])[0]+'_unsigned.bin'
    capsule_signed   = os.path.splitext(d['image_name'])[0]+'_signed.bin'
    with open(capsule_unsigned, 'wb') as f, open(d['image_name'], 'rb') as f1:
      f.write(capsule_head)
      f.write(f1.read())
      f.write(b'\xff'*capsule_padsize)

    cpldcap=sign.Signing(capsule_unsigned, CFM_PC_TYPE, self.csk_id, self.rk_prv, self.csk_prv)
    cpldcap.set_signed_image(capsule_signed)
    cpldcap.sign()


  def build_cfm_capsule(self, image_name=None):
    """ build cpld update capsule """
    self.cfm_capsule = 'cfm_capsule_signed.bin' if image_name is None else image_name
    self.build_pfm()
    [self.build_single_capsule(k) for k in self.lst_cpld]

    with open('cfm_unsigned.bin', 'wb') as f:
      with open('cfm_pfm_signed.bin', 'rb') as f1:
        f.write(f1.read())
      for k in self.lst_cpld:
        d=self.manifest[k]
        fname=os.path.splitext(d['image_name'])[0]+'_signed.bin'
        with open(fname, 'rb') as f2:
          f.write(f2.read())

    cfmcap=sign.Signing('cfm_unsigned.bin', CFM_PC_TYPE, self.csk_id, self.rk_prv, self.csk_prv)
    cfmcap.set_signed_image(self.cfm_capsule)
    cfmcap.sign()


def main(args):
  """ command line execution inteface

  Execution command in command prompt::

    # Create AFM capsule
    >python -m intelprot.capsule -start_afm
    >python -m intelprot.capsule afm -a <afm_manifest_json> -b <BMC image>

    # create decommission capsule
    >python -m intelprot.capsule decomm -rk <root private key> -csk <csk private key> -id <CSK ID>

    # create key cancellation cerificate
    >python -m intelprot.capsule kcc -rk <root private key> -id <CSK ID> -type <Protect Content type>

    # re-sign a capsule with a differnt CSK_ID, can also and update pfm parameters (svn, bkc_ver, pfm_rev, oem_data)
    >python -m intelprot.capsule stgcap -cap <signed bmc, ifwi or cpld capsule> -rk <root private key> -csk <csk private key> -id <new csk_id>

  """

  parser = argparse.ArgumentParser(description='build capsule from manifest json file.')
  parser.add_argument('-start_afm', action='store_true', help='start AFM: generate manifest reference file')
  parser.add_argument('-start_cfm', action='store_true', help='start CFM: generate manifest reference file')
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
  kcccap.add_argument('-id', '--csk_id',    metavar="[CSK ID to be cancelled]",  dest='csk_id', help='CSK ID to be cancelled')
  kcccap.add_argument('-type', '--pctype',  metavar="[PC Type]",  dest='pc_type', help='PC Type for Key Cancellation Certificate, select one from list [capld_cap, pch_pfm, pch_cap, bmc_pfm, bmc_cap] build all types of KCC if no input')

  stgcap = subparser.add_parser('stgcap')
  stgcap.add_argument('-cap',  '--stg_cap',  metavar="[staging capsule]",  dest='stg_cap', help='good staging capsule to update parameters, including bmc, ifwi, and cpld update capsule')
  stgcap.add_argument('-rk',   '--root_prv', metavar="[root private key]", dest='rk_prv',  help='root private key (PEM format) to build capsule')
  stgcap.add_argument('-csk',  '--csk_prv',  metavar="[CSK private key ]", dest='csk_prv', help='CSK private key (PEM format) to build capsule')
  stgcap.add_argument('-id',   '--csk_id',   metavar="[CSK ID number ]",   dest='csk_id',  help='CSK ID for the capsule')
  stgcap.add_argument('-svn',  '--svn_id',   metavar="[SVN number]",       dest='svn',     help='SVN number for the capsule')
  stgcap.add_argument('-bkc',  '--bkc_ver',  metavar="[bkc version]",      dest='bkc_ver', help='bkc version')
  stgcap.add_argument('-pfm',  '--pfm_rev',  metavar="[pfm revision]",     dest='pfm_rev', help='pfm revision')
  stgcap.add_argument('-oem',  '--oem_data', metavar="[oem data]",         dest='oem_data', help='add OEM data in pfm')

  cfmcap = subparser.add_parser('cfm')
  cfmcap.add_argument('-c', '--cfm_manifest', metavar="[CFM manifest]",  dest='cfm_m', help='cfm manifest json file')

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
      from intelprot import bmc
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

  if args.capsule == 'stgcap':
    print(args)
    # cap_image, rk_prv, csk_prv, csk_id, svn=None, bkc_ver=None, pfm_rev=None, oem_data=None
    args.csk_id = int(args.csk_id) if args.csk_id else None
    args.svn = int(args.svn) if args.svn else None
    args.bkc_ver = int(args.bkc_ver) if args.bkc_ver else None
    args.pfm_rev = int(args.pfm_rev) if args.pfm_rev else None
    args.oem_data = int(args.oem_data) if args.oem_data else None
    updcap = STG_Capsule(args.stg_cap, args.rk_prv, args.csk_prv, args.csk_id, args.svn, args.bkc_ver, args.pfm_rev, args.oem_data)
    updcap.build_cap()

  if args.start_cfm:
    print("-- generated cfm_manifest.json reference file")
    src_json_file = os.path.join(os.path.dirname(__file__), 'json', 'cfm_manifest.json')
    dst_json_file = os.path.join(os.getcwd(), 'cfm_manifest.json')
    shutil.copyfile(src_json_file, dst_json_file)
    lst_keys = ('key_root_prv.pem', 'key_csk_prv.pem')
    for f in lst_keys:
      src_f = os.path.join(os.path.dirname(__file__), 'keys', 'eaglestream', f)
      dst_f = os.path.join(os.getcwd(), f)
      shutil.copyfile(src_f, dst_f)


  if args.capsule == 'cfm' and args.cfm_m != None:
    print("-- build cfm staging capsule only" )
    mycfm=CFM(args.cfm_m)
    mycfm.build_cfm_capsule()

if __name__ == '__main__':
  main(sys.argv[1:])
