#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

   PFR binary image parsing utility functions

"""
from __future__ import print_function
from __future__ import division

import os, sys, re, json, difflib, urllib3, requests
import binascii, struct, codecs, base64, hashlib
from functools import partial
import subprocess, argparse, os

BUFSIZE = 0x1000
CPLD_MAILBOX_JSON = os.path.join(os.path.dirname(__file__), r'json\cpld_mailbox.json')

def get_hash256(fname_or_bdata, start_addr=None, end_addr=None):
  """ calculate SHA 256

  It calculates hash256 32 bytes either from a binary file or from binary data in bytes/bytearray
  If fname_or_bdata is a file, default from offset 0 to the end of file.
  Input start, end address if only calculate hash from partial data from the binary file.

  :param fname_or_bdata: file name of the binary image with path, or binary data read from a binary file
  :param start_addr: start address, optional.
    It is needed if fname_or_bdata is a file and not start from the begining of the file
  :param end_addr: end address, optional.
    It is needed if fname_por_bdata is a file, and not to the end of the file

  :returns hash256: hex string of digest

  """
  if isinstance(fname_or_bdata, (bytes, bytearray)):
    # bytes or bytearray
    bdata = fname_or_bdata
  elif os.path.exists(fname_or_bdata):
    start_addr = 0 if (start_addr is None) else start_addr
    end_addr = os.stat(fname_or_bdata).st_size if (end_addr is None) else end_addr
    with open(fname_or_bdata, 'rb') as f:
      f.seek(start_addr)
      bdata=f.read(end_addr - start_addr)
  hash256=hashlib.sha256(bdata).hexdigest()
  return hash256


def get_hash384(fname_or_bdata, start_addr=None, end_addr=None):
  """ calculate SHA 384

  It calculates hash384 48 bytes either from a binary file or from binary data in bytes/bytearray
  If fname_or_bdata is a file, default from offset 0 to the end of file.
  Input start, end address if only calculate hash from partial data from the binary file.

  :param fname_or_bdata: file name of the binary image with path, or binary data read from a binary file
  :param start_addr: start address, optional.
    It is needed if fname_or_bdata is a file and not start from the begining of the file
  :param end_addr: end address, optional.
    It is needed if fname_por_bdata is a file, and not to the end of the file

  :returns hash256: hex string of digest

  """
  if isinstance(fname_or_bdata, (bytes, bytearray)):
    # bytes or bytearray
    bdata = fname_or_bdata
  elif os.path.exists(fname_or_bdata):
    start_addr = 0 if (start_addr is None) else start_addr
    end_addr = os.stat(fname_or_bdata).st_size if (end_addr is None) else end_addr
    with open(fname_or_bdata, 'rb') as f:
      f.seek(start_addr)
      bdata=f.read(end_addr - start_addr)
  hash384=hashlib.sha384(bdata).hexdigest()
  return hash384


def bin_compare_bytes(f1, f2, st_addr, size_bytes):
  """compare two binary files from start addr

  :param f1: first file to compare.
  :param f2: second file to compare.
  :param st_addr: start address to compare
  :param size_bytes: size of bytes to compare.
  :returns rtn: True/False
  """
  rtn = True
  with open(f1, 'rb') as fp1, open(f2, 'rb') as fp2:
    fp1.seek(st_addr), fp2.seek(st_addr)
    total, bufsize = 0, 16
    while total < size_bytes:
      temp1, temp2 =fp1.read(bufsize), fp2.read(bufsize)
      total += 16
      if temp1 != temp2:
        print("index: 0x%x"%(st_addr+total))
        print("%-30s"%f1, binascii.hexlify(temp1))
        print("%-30s"%f2, binascii.hexlify(temp2))
        rtn=False
  return rtn


def bin_compare_region(fn1, start1, end1, fn2, start2, end2):
  """compare region from two files

  :param fn1: the first file to compare.
  :param start1: start address of the file fn1.
  :param end1: end address of file fn1
  :param fn2: the second file to compare.
  :param start2: start address of the file fn2.
  :param end2: end address of file fn2.
  :returns rtn: True/False.
  """
  rtn = True
  s1, s2 = (end1-start1), (end2-start2)
  size_bytes = s1
  if s1 > s2: size_bytes = s2
  with open(fn1, 'rb') as f1, open(fn2, 'rb') as f2:
    f1.seek(start1)
    f2.seek(start2)
    total, bufsize = 0, 16
    while total < size_bytes:
      temp1, temp2 =f1.read(bufsize), f2.read(bufsize)
      total += 16
      if temp1 != temp2:
        print("index: 0x%x, 0x%x"%(start1+total, start2+total))
        print("%-30s"%fn1, binascii.hexlify(temp1))
        print("%-30s"%fn2, binascii.hexlify(temp2))
        rtn=False
  return rtn


def bin_compare(f1, f2):
  """ compare two binary files

  :param f1: filename of the first image.
  :param f2: filename of the second image
  :returns rtn: True/False of compare results. True: f1 and f2 are exactly same.
  """
  with open(f1, 'rb') as fp1, open(f2, 'rb') as fp2:
    b1 = b2 = True
    while b1 or b2:
      b1, b2 = fp1.read(BUFSIZE), fp2.read(BUFSIZE)
      if b1 != b2:
        return False
    return True


def bin_hexdump(fbin, st_addr=None, end_addr=None, fout=None):
  """ dump binary file as hex string and save to a file

  This function dump partial or whole binary image to a text file.
  The text file is hex string bytes with address information.

  :param fbin: input image filename.
  :param st_addr: start address, optional. Defaul is from beginning of the image
  :param end_addr: end address, optionsl. Default is to the end of image
  :param fout: output image filename, optional. Default is fbin_<st_addr>_<end_addr>_hexdump.txt
  """
  if st_addr is None: st_addr = 0
  if end_addr is None: end_addr = os.stat(fbin).st_size
  addr = st_addr
  if fout is None:
    fout = os.path.splitext(fbin)[0]+'_0x%x_0x%x_hexdump.txt'%(st_addr, end_addr)
  with open(fbin, 'rb') as f1, open(fout, 'w') as f2:
    f1.seek(st_addr)
    for bdata in iter(partial(f1.read, 16), b''):
       f2.write("0x%07X | "%addr)
       for i in range(len(bdata)):
         f2.write(" %02x"%bdata[i])
       f2.write("\n")
       addr += 16
       if addr >= end_addr: break


def bin_decomp(fbin, st_addr, end_addr, fout=None):
  """ decompost a region from a binary file

  decompost a region from start to end address from a binary file and write the region content to a file
  the output file name is optional. The default output file name is input file name with address range

  :param fbin: filename of a binary file
  :param st_addr: start address of the region
  :param end_addr: end address of the region
  :param fout: output image file name

  :returns None
  """
  if fout == None:
    fout = os.path.splitext(fbin)[0]+'_from_0x%0x_to_0x%0x'%(staddr, endaddr)+'.bin'
  with open(fbin, 'rb') as f1, open(fout, 'wb') as f2:
    f1.seek(st_addr)
    f2.write(f1.read(end_addr-st_addr))


def bin_search_tag(fbin, st_tag):
  """search a tag from a binary file

  The st_tag is either a double word little endian integer or bytes/bytearray format

  :param fbin: input filename
  :param dw_tag: double word tag, example 0x02B3CE1D
  :returns lst_addr: list of addresses of all occurances of the tag
  """
  if not isinstance(st_tag, (bytes, bytearray)):
    st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
  with open(fbin, 'rb') as f:
    lst_addr = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), f.read())]
  return lst_addr


def bin_search_bytes(fbin, st_tag, relative_offset, size_of_bytes):
  """search bytes from a binary file relative to a start tag

  This function search a binary file and return the interested bytes relative to the start tag location
  It is useful to find a varibale number of bytes relative to a known tag.

  :param fbin: input filename
  :param st_tag: start of a tagflag. st_tag is wither bytes or integer, example b'__PFRS__', b'__KEYM__' or 0x02B3CE1D, 0xB6EAFD19
  :param relative_offset: relative offset in bytes to the st_tag
  :param size_of_bytes: size of return bytes
  :returns rtn_bytes: return bytes of size size_of_bytes

  example::

    ##. find 32 bytes of data that is relative 16 bytes after integer tag 0xB6EAFD19 from a_file
    >>>pfr_utility.bin_search_bytes(a_file, 0xB6EAFD19, 16, 32)
    ##. find 32 bytes of data that is 80 bytes after tag b'__KEYM__'
    >>>pfr_utility.bin_search_bytes(a_file, b'__KEYM__', 80, 32)

  """
  if not isinstance(st_tag, (bytes, bytearray)):
    st_tag = st_tag.to_bytes((st_tag.bit_length()+7)//8, 'little')
  with open(fbin, 'rb') as f:
    lst_idx = [(hex(m.start(0))) for m in re.finditer(re.escape(st_tag), f.read())]
    #print(lst_idx)
    idx = int(lst_idx[-1], 0)
    f.seek(0)
    f.seek(idx + relative_offset)
    rtn_bytes = f.read(size_of_bytes)
  return rtn_bytes


def insert_bytes(fbin, st_addr, new_bytes, fout=None):
  """insert bytes to an image from a start address

  This function insert bytes to an image

  :param fbin: input binary filename
  :param st_addr: start offset of the file
  :param new_bytes: bytes or bytearray to be inserted
  :param fout: output image filename, optional. Default is fbin_insert.bin
  """
  if fout is None:
    fout = os.path.splitext(fbin)[0]+"_insert.bin"
  with open(fbin, 'rb') as f1, open(fout, 'wb') as f2:
    f1.seek(0)
    f2.write(f1.read(st_addr))
    f2.write(new_bytes)
    f2.write(f1.read())


def replace_bytes(fbin, start_addr, new_bytes, fout=None):
  """replace bytes from a start address for a binary image

  This function is replace variable number of bytes of a binary image and save it as a new image

  :param fbin: input image file
  :param start_addr: start address to replace
  :param new_bytes: new bytes to replace from an image
  :param fout: output image filename, optional. Default is fbin_replaced.bin
  """
  if fout is None:
    fout = os.path.splitext(fbin)[0]+"_replaced.bin"
  with open(fbin, 'rb') as f1, open(fout, 'wb') as f2:
    f1.seek(0)
    f2.write(f1.read(start_addr))
    f2.write(new_bytes)
    f1.seek(start_addr + len(new_bytes))
    f2.write(f1.read())


def integrate_capsule(fbin, fcap, st_addr, fout=None):
  """integrate capsule to a pfr image

  This function integrate a capsule image to a pfr image.
  A new image file will be generated at the same folder of input image. The content from st_addr will be replaced with capsule image

  :param fbin: input pfr image
  :param fcap: signed capsule image to be added
  :param st_addr: start address to integrate
  :param fout: output filename, optional. default is fbin file name path with "_with_cap".bin

  """
  if fout is None:
    fout = os.path.splitext(fbin)[0] + '_with_capsule.bin'
  with open(fout, 'wb') as f1, open(fbin, 'rb') as f2, open(fcap, 'rb') as f3:
    f1.write(f2.read(st_addr))
    f1.write(f3.read())
    f2.seek(st_addr+ os.stat(fcap).st_size)
    f1.write(f2.read())


def bind_file_at_addr(inf_n, outf_n, offset_addr):
  """ combine two binary file together, read inf_n and write it to outf_n at offset_addr in bytes

  :param inf_n: input file name
  :param outf_n: output file name
  :param offset_addr: offset address

  """
  with open(outf_n, "r+b") as ofd, open(inf_n, 'rb') as ifd:
    ofd.seek(offset_addr)
    ofd.write(ifd.read())

def read_mailbox(bmc_ip_addr, username, password):
  """ Read CPLD host mailbox register using BMC OOB method

  This function use below command to read CPLD mailbox register::

    ipmitool -I lanplus -H <BMC_IP> -C 17 -U <username> -P <password> raw 6 0x52 0x09 0x70 0x7f 0x00
    #example:
    ipmitool -I lanplus -H 10.105.134.16 -C 17 -U debuguser -P 0penBmc1 raw 6 0x52 0x09 0x70 0x7f 0x00

  :param bmc_ip_addr: BMC IP address
  :param username: BMC OOB user username
  :param password: BMC OOB user password

  """
  #bmc_ip_addr = '10.105.134.16'
  #username, password = 'debuguser', '0penBmc1'
  cmdline = "ipmitool -I lanplus -H {} -C 17 -U {} -P {} raw 6 0x52 0x09 0x70 0x7f 0x00".format(bmc_ip_addr, username, password)
  result = subprocess.getoutput(cmdline).split('\n')
  result = ''.join(result)
  idx=result.index('de')
  result=result[idx:]   # get content from first identifier 'de'
  lst_cpld_mailbox = result.split(' ')
  return lst_cpld_mailbox

def decode_mailbox(lst_mailbox):
  """
  decode mailbox register value
  """
  lst_dec_keys_1 = ['00h','03h','05h', '07h', '08h', '0Bh', '10h','11h', '7Ah']

  lst_data = []
  [lst_data.append(int(i, 16)) for i in lst_mailbox]
  with open(CPLD_MAILBOX_JSON, 'r') as fp:
    mb = json.load(fp)
  #print("Mailbox - Name: Value")
  print("{a:8s} - {b:45s}: {c}".format(a="Mailbox", b="Name", c="Value (hex)"))
  print("---------------------------------------------------------------------")
  for k in mb:
    mb[k]['decode'] = ""
    if '-' in k:
      i, j = int(k.split('-')[0].strip('h'), 16), int(k.split('-')[1].strip('h'), 16)
      mb[k]['value'] = lst_data[i:j+1]
      #print(mb[k]['name'])
      if mb[k]['name'] == 'CPLD RoT Hash':
        temp = lst_data[i:j+1]
        rot_hash=""
        for i in temp[0:48]:
          rot_hash += "%02x"%(i)
        mb[k]['value'] = rot_hash
    else:
      i = int(k.strip('h'), 16)
      mb[k]['value'] = lst_data[i]

  for k in lst_dec_keys_1:
    #print(k, mb[k]['value'])
    k1= '0x%02X'%(mb[k]['value'])
    mb[k]['decode']=mb[k]['value_decode'][k1]

  #decode 09h
  if mb['08h']['value'] in [1, 2]:
    k1= '0x%02X'%(mb['09h']['value'])
    mb['09h']['decode']=mb['09h']['value_decode']["0x01-0x02"][k1]
  if mb['08h']['value'] == 3:
    k1= '0x%02X'%(mb['09h']['value'])
    mb['09h']['decode']=mb['09h']['value_decode']["0x03"][k1]

  #decode 0Ah 0x22 0010,0010
  mb['0Ah']['decode'] = ""
  temp = mb['0Ah']['value']
  for i in range(0, 8):
    if temp &(1<<i) != 0:
      if mb['0Ah']['decode'] != "":
        mb['0Ah']['decode'] += ' + ' + mb['0Ah']['value_decode']['Bit[{}]'.format(i)]
      else:
        mb['0Ah']['decode'] += mb['0Ah']['value_decode']['Bit[{}]'.format(i)]
  #deocde

  # display mailbox and decode
  for k in mb:
    if mb[k]['name'] != 'CPLD RoT Hash':
      if mb[k]['decode'] != "":
        print("{a:8s} - {b:45s}: {c:02x} --> {d}".format(a=k, b=mb[k]["name"], c=mb[k]["value"], d = mb[k]['decode']))
      else:
        print("{a:8s} - {b:45s}: {c:02x} ".format(a=k, b=mb[k]["name"], c=mb[k]["value"]))

  print("\n{a:8s} - {b:45s}: {c}".format(a="20h-5Fh", b=mb["20h-5Fh"]["name"], c=mb["20h-5Fh"]["value"]))


def main(args):
  """
    command line to read CPLD mailbox register remotely using ipmi, and decode it.

    You will need set bmc user username/password with OOB authority and also with BMC IP address.

    Read CPLD mailbox command line::

    >>python -m intel_pfr.utility mailbox -i <BMC_IP> -u <username> -p <password>


  """
  parser = argparse.ArgumentParser(description="-- PFR Utility")

  # read cpld mailbox
  subparser = parser.add_subparsers(dest='action')
  cmdmbx = subparser.add_parser('mailbox')
  cmdmbx.add_argument('-i', '--bmc_ip',   metavar="[BMC IP address]", dest='bmc_ip', help='BMC IP address')
  cmdmbx.add_argument('-u', '--username', metavar="[username]",  dest='username', help='BMC OOB user username')
  cmdmbx.add_argument('-p', '--password', metavar="[password]",  dest='password', help='BMC OOB user password')
  # read UFM
  cmdufm = subparser.add_parser('ufm')
  cmdufm.add_argument('-i', '--bmc_ip',   metavar="[BMC IP address]", dest='bmc_ip', help='BMC IP address')
  cmdufm.add_argument('-u', '--username', metavar="[username]",  dest='username', help='BMC OOB user username')
  cmdufm.add_argument('-p', '--password', metavar="[password]",  dest='password', help='BMC OOB user password')

  args = parser.parse_args(args)
  #print(args)
  if args.action == 'mailbox':
    lst_mailbox = read_mailbox(args.bmc_ip, args.username, args.password)
    #print(lst_mailbox)
    decode_mailbox(lst_mailbox)
  if args.action == 'ufm':
    print('-- add reading UFM later')

if __name__ == '__main__':
  main(sys.argv[1:])

