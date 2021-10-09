#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
   :platform: Linux, Windows
   :synopsis:

     This module includes all operations that are related to pfr keys, singing, verification opertaions, including:

     * PrivateKey class
     * PublicKey class
     * Calculation of a public key hash
     * Calculation of Public key X,Y
     * Get public key hash from private key
     * Sign a data using private key
     * Get signature R,S


"""
from __future__ import print_function
from __future__ import division

import os, sys, binascii, struct, hashlib, re, random

from ecdsa.curves import NIST384p, NIST256p
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
from subprocess import getoutput
import logging
logger = logging.getLogger(__name__)


class PrivateKey(object):
  """ class handle PFR private key

  Use class generator::

  *read_from_pem()
  *from_hexstr()

  """
  def __init__(self):
    self.key_pem = None
    self.sk = None
    self.curve = None
    self.pfr_ver = None
    self.vk = None
    self.hashbuffer = None

  @classmethod
  def read_from_pem(cls, key_pem):
    """ read from pem key

    :param key_pem: key file in PEM format

    """
    self = cls()
    if get_curve(key_pem) == 'NIST256p':
      hashfunc = hashlib.sha256
    if get_curve(key_pem) == 'NIST384p':
      hashfunc = hashlib.sha384

    self.key_pem = key_pem
    with open(self.key_pem, 'rt') as f:
      self.sk=SigningKey.from_pem(f.read(), hashfunc)
    self.curve = self.sk.curve.name
    self.pfr_ver = 3 if self.curve is 'NIST384p' else 2
    self.vk = self.sk.get_verifying_key()
    self.get_hashbuffer()
    return self


  @classmethod
  def from_hexstr(cls, prvkey_hex, curve=NIST384p, hashfunc=hashlib.sha384):
    """ Generate ECDSA private key from its integer converted from hex string

    :param prvkey_hex: hex string representing a ECDSA private key integer
    :type string: str
    :param curve: curve object in ecdsa, default is NIST384p
    :param hashfunc: hash function, default is SHA384

    """
    self = cls()
    prvkey_value = int(prvkey_hex, 16)
    self.sk = SigningKey.from_secret_exponent(prvkey_value, NIST384p, hashlib.sha384)
    self.curve = self.sk.curve.name
    self.pfr_ver = 3 if self.curve is 'NIST384p' else 2
    self.vk = self.sk.get_verifying_key()
    self.get_hashbuffer()
    return self


  def save_to_pem(self, key_pem):
    """ save to PEM format key file

    :param key_pem: file name of PEM format key

    """
    with open(key_pem, 'wt') as f:
      f.write(self.sk.to_pem().decode('utf-8'))

  def get_pubkey_xy(self):
    """ get public key X, Y in bytes format """
    if self.pfr_ver == 3:
      self.x, self.y = self.vk.to_string().hex()[:96], self.vk.to_string().hex()[96:]
    elif self.pfr_ver == 2:
      self.x, self.y = self.vk.to_string().hex()[:64], self.vk.to_string().hex()[64:]

    self.X, self.Y = bytes.fromhex(self.x), bytes.fromhex(self.y)
    if self.pfr_ver == 2:
      self.X += bytearray(16)
      self.Y += bytearray(16)
    return (self.X, self.Y)

  def get_hashbuffer(self):
    """ get publick key hashbuffer

    Calculate 48 bytes or 32 bytes Public Key hash buffer

    """
    if self.pfr_ver == 3:
      x, y = self.vk.to_string().hex()[:96], self.vk.to_string().hex()[96:]
      lx, ly = [x[i:i+2] for i in range(0,len(x), 2)], [y[i:i+2] for i in range(0,len(y), 2)]
      qx, qy=list(reversed(lx)), list(reversed(ly))
      qxy="".join(qx)+"".join(qy)
      self.hashbuffer = hashlib.sha384(binascii.unhexlify(qxy)).hexdigest()
      self.hashfunc = hashlib.sha384
    elif self.pfr_ver == 2:
      x, y = self.vk.to_string().hex()[:64], self.vk.to_string().hex()[64:]
      lx, ly = [x[i:i+2] for i in range(0,len(x), 2)], [y[i:i+2] for i in range(0,len(y), 2)]
      qx, qy=list(reversed(lx)), list(reversed(ly))
      qxy="".join(qx)+"".join(qy)
      self.hashbuffer = hashlib.sha256(binascii.unhexlify(qxy)).hexdigest()
      self.hashfunc = hashlib.sha256
    self.x, self.y = x, y
    self.X, self.Y = bytes.fromhex(self.x), bytes.fromhex(self.y)
    if self.pfr_ver == 2:
      self.X += bytearray(16)
      self.Y += bytearray(16)

  def verify_pair(self, pubkey):
    """ check if it is a pair of private key with a given public key

    :param pubkey: public key in PEM format

    """
    qxy = self.vk.to_string().hex()
    with open(pubkey) as f:
      vk2 = VerifyingKey.from_pem(f.read())
    qxy2 = vk2.to_string().hex()
    return (qxy1 == qxy2)


class PublicKey(object):
  """ class handling PFR public key operations

  Use class generator::

    *read_from_pem()
    *from_x_curve()

  """
  def __init__(self):
    self.key_pem = None
    self.vk = None
    self.curve=None
    self.pfr_ver = None
    self.hashbuffer = None
    self.hashfunc = None

  @classmethod
  def read_from_pem(cls, key_pem):
    """ read from pem key

    :param key_pem: file name of key in PEM format

    """
    self = cls()
    self.key_pem = key_pem
    with open(self.key_pem, 'rt') as f:
      self.vk=VerifyingKey.from_pem(f.read())
    self.curve = self.vk.curve.name
    self.pfr_ver = 3 if self.curve is 'NIST384p' else 2
    self.get_hashbuffer()
    return self

  def get_hashbuffer(self):
    """ get hashbuffer

    Calculate public key hash buffer

    """
    if self.pfr_ver == 3:
      x, y = self.vk.to_string().hex()[:96], self.vk.to_string().hex()[96:]
      lx, ly = [x[i:i+2] for i in range(0,len(x), 2)], [y[i:i+2] for i in range(0,len(y), 2)]
      qx, qy=list(reversed(lx)), list(reversed(ly))
      qxy="".join(qx)+"".join(qy)
      self.hashbuffer = hashlib.sha384(binascii.unhexlify(qxy)).hexdigest()
      self.hashfunc = hashlib.sha384
    elif self.pfr_ver == 2:
      x, y = self.vk.to_string().hex()[:64], self.vk.to_string().hex()[64:]
      lx, ly = [x[i:i+2] for i in range(0,len(x), 2)], [y[i:i+2] for i in range(0,len(y), 2)]
      qx, qy=list(reversed(lx)), list(reversed(ly))
      qxy="".join(qx)+"".join(qy)
      self.hashbuffer = hashlib.sha256(binascii.unhexlify(qxy)).hexdigest()
      self.hashfunc = hashlib.sha256
    self.x, self.y = x, y
    self.X, self.Y = bytes.fromhex(self.x), bytes.fromhex(self.y)
    if self.pfr_ver == 2:
      self.X += bytearray(16)
      self.Y += bytearray(16)

  def get_pubkey_xy(self):
    """ get public key X, Y in bytes format """
    if self.pfr_ver == 3:
      self.x, self.y = self.vk.to_string().hex()[:96], self.vk.to_string().hex()[96:]
    elif self.pfr_ver == 2:
      self.x, self.y = self.vk.to_string().hex()[:64], self.vk.to_string().hex()[64:]

    self.X, self.Y = bytes.fromhex(self.x), bytes.fromhex(self.y)
    if self.pfr_ver == 2:
      self.X += bytearray(16)
      self.Y += bytearray(16)
    return (self.X, self.Y)

  @classmethod
  def from_x_curve(cls, X, curve=NIST384p):
    """ generate ECDSA public key from X value and its curve

    :param X: hex string of ECDSA public key component X
    :type string: str
    :param curve: curve in ecsdsa, default is NIST384p

    """
    self=cls()
    self.x = X
    self.curve = curve
    comp_str = "02" + X  # uncompressed format leading with '02'
    self.vk = VerifyingKey.from_string(bytearray.fromhex(comp_str), curve=NIST384p)
    #print(vk.to_string("uncompressed").hex())
    self.curve = self.vk.curve.name
    self.pfr_ver = 3 if self.curve is 'NIST384p' else 2
    self.get_hashbuffer()
    return self


    def save_to_pem(self, key_pem):
      """ save the instance to a PEM format key file

      :param key_pem: key file name in PEM format

      """
      with open(key_pem, 'wt') as f:
        f.write(self.vk.to_pem().decode('utf-8'))

def get_eckey_type(key_pem):
  """ get EC key type public or private from PEM format key

      return "public", "private", or 'invalid'

  :param key_pem: EC key in PEM format

  """
  with open(key_pem, 'rt') as f:
    key=f.read()
  if 'PUBLIC'  in key: return 'public'
  elif 'PRIVATE' in key: return 'private'
  else: return 'invalid'

def get_rk_hashbuffer(rk_key):
  """ get root key hash buffer for provising verification
  return hashbuffer in hex string format

  :param rk_key: root key in pem format, wither private or public key

  """
  if get_eckey_type(rk_key) is 'private':
    rk = PrivateKey().read_from_pem(rk_key)
  if get_eckey_type(rk_key) is 'public':
    rk = PublicKey().read_from_pem(rk_key)
  return rk.hashbuffer

def get_curve(key_pem):
  """ get curve name of a key in pem format

  :param key_pem: key in PEM format
  :return curve.name: 'NIST384p' or 'NIST256p'

  """
  with open(key_pem, 'rt') as f:
    key=f.read()
  if 'PUBLIC' in key:
    k=VerifyingKey.from_pem(key)
  elif 'PRIVATE' in key:
    k=SigningKey.from_pem(key)
  return k.curve.name

def get_curve_baselen(key_pem):
  """ get curve name and baselen of a key in pem format

  :param key_pem: key in PEM format
  :return: (curve.baselen, curve.name)
      curve.baselen: 48, 32
      curve.name: 'NIST384p' or 'NIST256p'
  """
  with open(key_pem, 'rt') as f:
    key=f.read()
  if 'PUBLIC' in key:
    k=VerifyingKey.from_pem(key)
  elif 'PRIVATE' in key:
    k=SigningKey.from_pem(key)
  return (k.curve.baselen, k.curve.name)


def get_pfr_version(key_pem):
  """ get pfr version 2.0, 3.0 from key in pem format
  If curve.name: 'NIST384p' or 'NIST256p'
  :param key_pem: key in PEM format
  :return: pfr_version, 2 or 3
  """
  return 3 if get_curve(key_pem) == 'NIST384p' else 2


def get_hash_from_XY(X, Y):
  """ calculate public key hash from its component X and Y

  :param X: public key component X in hex string, X is 32 bytes for PFR 2.0, it is 48 bytes for PFR 3.0
  :type string: str
  :param Y: public key component Y in hex string
  :type string: str
  :return: keyhash
  :rtype: str

  """
  qx =''.join(X[i: i+2] for i in range(len(X), -2, -2))
  qy =''.join(Y[i: i+2] for i in range(len(Y), -2, -2))
  qxy = qx+qy
  if len(X) == 64 and len(Y) == 64:
    keyhash = hashlib.sha256(binascii.unhexlify(qxy)).hexdigest()
  elif len(X) == 96 and len(Y) == 96:
    keyhash = hashlib.sha384(binascii.unhexlify(qxy)).hexdigest()
  return keyhash


def verify_ec_keypair(pub_key_pem, prv_key_pem):
  """verify EC key is a pair

  This function validates the input public and private keys are a pair

  :param pub_key_pem: public key in PEM format
  :param prv_key_pem: private key in PEM format
  :returns Bool rtn: True/False - Pass/Fail
  """
  with open(prv_key_pem) as f:
    sk = SigningKey.from_pem(f.read())
  vk1 = sk.get_verifying_key()
  qxy1 = vk1.to_string().hex()

  with open(pub_key_pem) as f:
    vk2 = VerifyingKey.from_pem(f.read())
  qxy2 = vk2.to_string().hex()
  print('qxy1=%s, qxy2=%s'%(qxy1, qxy2))
  return (qxy1 == qxy2)


def signature_RS(signature):
  """ extract R, S from a signature binary

  :param signature: binary data of a signature
  :return: (R, S)
  :rtype: hex string

  """
  if len(signature) == 96:
    G = NIST384p.generator
  elif len(signature) == 64:
    G = NIST256p.generator
  order = G.order()
  (r, s) = ecdsa.util.sigdecode_der(signature, order)
  (R,S) = hex(r), hex(s)


def sign_data(pvt_key_pem, data):
  """
    sign data and return signature

  :param pvt_key_pem : private key in PEM format
  :param data: data to be signed in bytes format
  :type bytes: bytes
  :return: signature
  :rtype: bytes

  """
  with open(pvt_key_pem) as f:
    if get_curve(pvt_key_pem) == 'NIST256p':
      sk = SigningKey.from_pem(f.read(), hashlib.sha256)
    elif get_curve(pvt_key_pem) == 'NIST384p':
      sk = SigningKey.from_pem(f.read(), hashlib.sha384)
  signature = sk.sign_deterministic(data, sigencode=sigencode_der)
  return signature


def get_RS_signdata(pvt_key_pem, data):
  """
  Calculate signature component R and S from sign data and private key

  :param pvt_key_pem: private key in pem format
  :param data: data to be signed in bytes format
  :type bytes: bytes
  :return: (R, S) components in Bytes format
  :rtype: tuple of Bytes

  """
  if get_curve(pvt_key_pem) ==  'NIST256p':
    hashfunc = hashlib.sha256
    rs_size = 32
    pfr_version = 2
  elif get_curve(pvt_key_pem) == 'NIST384p':
    hashfunc = hashlib.sha384
    rs_size = 48
    pfr_version = 3

  with open(pvt_key_pem) as f:
    sk = SigningKey.from_pem(f.read(), hashfunc)

  signature = sk.sign_deterministic(data, hashfunc, sigencode=sigencode_der)
  print('signature:', signature.hex(), 'length:', len(signature.hex()))

  len_r=signature[3]
  print('len_r: ', len_r, 'signature[4]: ', signature[4])
  if (len_r == rs_size+1) and (signature[4] == 0x00):
    R = signature[5:5+rs_size]
  else:
    R = signature[4:4+rs_size]
  len_s=signature[len_r+5]
  if (len_s == rs_size+1) and (signature[len_r+6] == 0x00):
    S = signature[(len_r+7):(len_r+7+rs_size)]
  else:
    S = signature[(len_r+6):(len_r+6+rs_size)]
  if int(pfr_version) == 2:
    R += bytes(b'\x00'*16)
    S += bytes(b'\x00'*16)
  print("R : ", R.hex())
  print("S : ", S.hex())
  return (R, S)


def verify_signature_from_prvkey(prv_key_pem, R, S, data):
  """
  Verify signature with Signature Component R, S, private key PEM and signed data,
  assert with verification key, vk.verify(sig, data, hashlib.sha256, sigdecode=sigdecode_der)

  :param prv_key_pem : private key in PEM format
  :param R: signature component R in bytes
  :param S: signature component S in bytes
  :param data : data signed (in bytes)
  :return: True/False - Pass or Failure with raised error
  :rtype: Bool
  """
  if get_curve(prv_key_pem) == 'NIST256p':
    hashfunc = hashlib.sha256
    rs_size = 32
  if get_curve(prv_key_pem) == 'NIST384p':
    hashfunc = hashlib.sha384
    rs_size = 48
  with open(prv_key_pem) as f:
    sk = SigningKey.from_pem(f.read(), hashfunc)

  vk = sk.get_verifying_key()
  R, S = R[0:rs_size], S[0:rs_size]
  r, s = int.from_bytes(R, byteorder='big'), int.from_bytes(S, byteorder='big')
  #print("r, s =", r, s)
  signature = sigencode_der(r, s, random.randrange(100, 200))
  print("-- signature :", signature.hex())
  try:
    assert vk.verify(signature, data, hashfunc, sigdecode=sigdecode_der)
  except:
    raise
    return False
  return True


def verify_signature(pub_key_pem, R, S, data):
  """
  Verify signature with Signature Component R, S, private key PEM and signed data,
  assert with verification key, vk.verify(sig, data, hashlib.sha256, sigdecode=sigdecode_der)

  :param pub_key_pem : public key that is extracted from private sign key
  :param R: signature component R in bytes
  :param S: signature component S in bytes
  :param data : data signed (in Bytes)
  :return: True/False - Pass or Failure with raised error
  :rtype: Bool
  """
  with open(pub_key_pem) as f:
    vk = VerifyingKey.from_pem(f.read())
  r, s = int.from_bytes(R, byteorder='big'), int.from_bytes(S, byteorder='big')
  try:
    if get_curve(prv_key_pem) == 'NIST256p':
      order = NIST256p.generator.order()
      signature = sigencode_der(r, s, order)
      assert vk.verify(signature, data, hashlib.sha256, sigdecode=sigdecode_der)
    elif get_curve(prv_key_pem) == 'NIST384p':
      order = NIST384p.generator.order()
      signature = sigencode_der(r, s, order)
      assert vk.verify(signature, data, hashlib.sha384, sigdecode=sigdecode_der)
  except:
    raise
    return False
  return True

