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
import pathlib, json, subprocess
import argparse

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
  #print("-- signature :", signature.hex())
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


class OpenSpdm_Keys(object):
  """
  generate openspdm keys and create template

  """
  def __init__(self):
    """ constructor """
    template_json = os.path.join(os.path.dirname(__file__), 'json', 'afm_manifest.json')
    with open(template_json, 'r') as f:
      self.tmplate_manifest = json.load(f)

    self.openssl_cnf = \
    """### REF: https://www.openssl.org/docs/man1.1.1/man3/ASN1_generate_nconf.html

    [ v3_end ]
    basicConstraints = critical,CA:false
    keyUsage = nonRepudiation, digitalSignature, keyEncipherment
    subjectKeyIdentifier = hash
    subjectAltName = otherName:1.3.6.1.4.1.412.274.1;UTF8:ACME:WIDGET:1234567890
    extendedKeyUsage = critical, serverAuth, clientAuth, OCSPSigning

    [ v3_inter ]
    basicConstraints = CA:true
    keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
    subjectKeyIdentifier = hash
    extendedKeyUsage = critical, serverAuth, clientAuth
    """

  def gen_openssl_cnf(self):
    """ generate a openssl.cnf file with text defined in self.openssl_cnf
     remove leading blank space
    """
    tmp='\n'.join([x.strip() for x in self.openssl_cnf.split('\n')])
    with open('openssl.cnf', 'w') as f:
      f.write(tmp)

  def create_Certchain_EcP384(self, dir='EcP384'):
    """
    generate new key and self-sign Certchain for OpenSpdm
    save all files in a folder. Default is EcP384 under work directory, user can copy whole folder to
    openspdm_build directory, C:\shuang4\Work\openspdm-master\Build\DEBUG_VS2019\X64\EcP384

    :param dir: directory name to save all generated files, optional, default is 'EcP384' under work directory

    """
    str_cmd_windows = \
    """
    openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
    openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -subj "/CN=intel test ECP384 CA"
    openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=intel test ECP384 intermediate cert"
    openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "/CN=intel test ECP384 requseter cert"
    openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "/CN=intel test ECP384 responder cert"
    openssl pkey -in ca.key -outform der -out ca.key.der
    openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
    openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 365 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
    openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 365 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
    openssl asn1parse -in ca.cert -out ca.cert.der
    openssl asn1parse -in inter.cert -out inter.cert.der
    openssl asn1parse -in end_requester.cert -out end_requester.cert.der
    openssl asn1parse -in end_responder.cert -out end_responder.cert.der
    type ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
    type ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
    openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
    openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
    openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
    openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
    openssl x509 -inform der -in end_responder.cert.der -pubkey -noout > end_responder_pubkey.pem
    """
    work_path  = os.getcwd()
    pathlib.Path(os.path.join(work_path, dir)).mkdir(parents=True, exist_ok=True)
    self.gen_openssl_cnf() # generate a openssl.cnf file
    # check openssl version, old version may have problem
    if self.verify_openssl_version():
      os.chdir(os.path.join(work_path, dir))
      #print(str_cmd_windows)
      [os.system(x.strip()) for x in str_cmd_windows.split('\n')]
      os.chdir(work_path)
    else:
      print("Error: Please update openssl and configure it in system path")

  def verify_openssl_version(self):
    """ verify openssl is in system path and not use old version """
    rtn = subprocess.getoutput('openssl version')
    ver, year = rtn.split(' ')[1], rtn.split(' ')[-1]
    print("openssl version: {}".format(rtn))
    result=True if int(year) >=2021 else False
    return result

  def create_afm_manifest(self, measurement_size = 128):
    """ create afm_manifest_openspdm.json to build afm capsule using capsule module """
    MEASUREMENT_BLOCK_NUMBER  = 5  # constant for openspdm
    MEASUREMENT_MANIFEST_SIZE = measurement_size # default is 128 bytes
    template_json = os.path.join(os.path.dirname(__file__), 'json', 'afm_manifest.json')
    with open(template_json, 'r') as f:
      self.ospdm_manifest = json.load(f)
    """
    for k in self.ospdm_manifest['devices'][0]:
      #print(k)
      print("self.ospdm_manifest['devices'][0]['{}'] = {}".format(k, self.ospdm_manifest['devices'][0][k]))
    for k in self.ospdm_manifest['devices'][0]['measurement'][0]:
      print("self.ospdm_manifest['devices'][0]['measurement'][0]['{}'] = {}".format(k, self.ospdm_manifest['devices'][0]['measurement'][0][k]))
    for k in self.ospdm_manifest['devices'][0]['measurement'][1]:
      print("self.ospdm_manifest['devices'][0]['measurement'][1]['{}'] = {}".format(k, self.ospdm_manifest['devices'][0]['measurement'][1][k]))
    for k in self.ospdm_manifest['devices'][0]['measurement'][2]:
      print("self.ospdm_manifest['devices'][0]['measurement'][2]['{}'] = {}".format(k, self.ospdm_manifest['devices'][0]['measurement'][2][k]))
    for k in self.ospdm_manifest['devices'][0]['measurement'][3]:
      print("self.ospdm_manifest['devices'][0]['measurement'][3]['{}'] = {}".format(k, self.ospdm_manifest['devices'][0]['measurement'][3][k]))
    for k in self.ospdm_manifest['devices'][0]['measurement'][4]:
      print("self.ospdm_manifest['devices'][0]['measurement'][4]['{}'] = {}".format(k, self.ospdm_manifest['devices'][0]['measurement'][4][k]))
    """
    kk = PrivateKey().read_from_pem(r'EcP384\end_responder.key')
    self.ospdm_manifest['devices'][0]['public_key_X']=kk.x
    self.ospdm_manifest['devices'][0]['public_key_Y']=kk.y

    measurement = []
    for i in range(0, MEASUREMENT_BLOCK_NUMBER):
      bdata=bytearray([i+1]*MEASUREMENT_MANIFEST_SIZE)
      measurement.append(hashlib.sha384(bdata).hexdigest())

    last_meas = []
    repeat_num, rest = int(MEASUREMENT_MANIFEST_SIZE/32), (MEASUREMENT_MANIFEST_SIZE-int(MEASUREMENT_MANIFEST_SIZE/32)*32)
    for i in range(0, repeat_num):
      last_meas.append(bytearray([MEASUREMENT_BLOCK_NUMBER]*32).hex())
    if rest != 0:
      last_meas.append(bytearray([MEASUREMENT_BLOCK_NUMBER]*rest).hex())

    for i in range(0, int(MEASUREMENT_BLOCK_NUMBER/32)):
      self.ospdm_manifest['devices'][0]['measurement'][i]['measurement'] = [measurement[i]]
    self.ospdm_manifest['devices'][0]['measurement'][MEASUREMENT_BLOCK_NUMBER-1]['measurement'] = [last_meas]

    with open('afm_manifest_openspdm.json', 'w') as f:
      json.dump(self.ospdm_manifest, f, indent=4)


def main(args):
  """
  command arguments for openspdm key and certificate chain generation

  """
  parser = argparse.ArgumentParser(description='openspdm keys')

  subparser = parser.add_subparsers(dest='openspdm')
  ospdmafm = subparser.add_parser('openspdm-afm')
  ospdmafm.add_argument('-a', '--afm_manifest',  metavar="[AFM manifest]",  dest='afm_m', help='create openspdm afm manifest json file')
  ospdmafm.add_argument('-p', '--path_folder',   metavar="[Key director(EcP384)]",  dest='key_dir', default='EcP384', help='key chains folder name')

  ospdmkey = subparser.add_parser('openspdm-keys')
  ospdmkey.add_argument('-p', '--path_folder',   metavar="[Openspdm keys path (EcP384)]",  dest='key_dir', default='EcP384', help='key chains folder name')
  args = parser.parse_args(args)

  #print("args={}".format(args))
  #print("args.openspdm = {}".format(args.key_dir))

  if args.openspdm == 'openspdm-keys':
    print("-- create openspdm keys in folder")
    ospdmkey= OpenSpdm_Keys()
    ospdmkey.create_Certchain_EcP384(args.key_dir)
    print("-- openspdm keys are generated in folder {}".format(os.path.join(os.getcwd(), args.key_dir)))

  if args.openspdm == 'openspdm-afm':
    print("-- create afm manifest for openspdm responder device")
    ospdmkey= OpenSpdm_Keys()
    ospdmkey.create_afm_manifest()
    print("-- an afm manifest file afm_manifest_openspdm.json is generated in folder {}".format(os.getcwd()))

if __name__ == '__main__':
  main(sys.argv[1:])
