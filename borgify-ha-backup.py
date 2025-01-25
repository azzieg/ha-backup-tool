#!/usr/bin/env python3

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
import gzip

# pip install pycryptodome
from Crypto.Cipher import AES

DESCRIPTION = '''
Decrypts and decompresses Home Assistant backups, so you can deduplicate, compress and encrypt them 
using your favourite backup solution. Don't reinvent the wheel.
'''
EPILOG='''
If you're looking for a deduplicating backup with compression and encryption support, consider
https://borgbackup.org/
'''

def parse_args():
  parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG)
  parser.add_argument('input_tar', help='encrypted backup archive to decrypt')
  parser.add_argument('output_tar', help='decrypted backup archive to write')
  parser.add_argument('-p', '--password', metavar='KEY',
                      help='encryption key, typically YOUR-ENCR-YPIO-NKEY-FROM-SETT-INGS')
  parser.add_argument('-l', '--list', action='store_true', help='Output processed archive entities')
  parser.add_argument('-c', '--compressed', action='store_true',
                      help='do not decompress subarchives')
  parser.add_argument('-d', '--delete', action='store_true',
                      help='remove the input archive after writing the output')
  return parser.parse_args()

# AES-128 encryption as implemented by Secure Tar (https://github.com/pvizeli/securetar).
# - Encryption key is a password hashed 100 times with SHA-256 and cropped to 128 bits.
# - CBC mode is used, so the file is seekable. It's very useful, see below!
# - IV is derived from a seed appended to the key and hashed like the password.
# - IV seed is stored in the first 16 bytes. PKCS7 padding is used at the end.
# - A header mode exists, but I did not see it used in the wild, so did not implement it.
#
# As of January 2025, Secure Tar also errorneously applies the padding before the last block. This 
# breaks the CRC location in GZIP files. Luckily, we can correctly read the uncompressed size and 
# Tarfile won't cross the EOF and won't trigger the CRC check. But it's a dumpster fire.
class AesFile:
  def __init__(self, password, file):
    self._key = AesFile._digest(password.encode())
    self._file = file
    self._eof = file.seek(0, os.SEEK_END)
    self.seek(-1, os.SEEK_END)
    self._eof -= self.read(1)[0]
    self.seek(0)

  def _digest(key):
    for _ in range(100):
      key = hashlib.sha256(key).digest()
    return key[:16]

  def _init(self, block):
    self._file.seek(block * 16)
    iv = self._file.read(16)
    if block == 0:
      iv = AesFile._digest(self._key + iv)
    self._aes = AES.new(self._key, AES.MODE_CBC, iv)
    self._buf = b''

  def _decrypt(self, blocks):
    return self._aes.decrypt(self._file.read(blocks * 16))

  def read(self, size):
    position = self._file.tell() - len(self._buf)
    if position + size > self._eof:
      size = self._eof - position
    assert size >= 0
    blocks = (size - len(self._buf) + 15) // 16
    assert blocks >= 0
    if blocks > 0:
      self._buf += self._decrypt(blocks)
    result = self._buf[:size]
    self._buf = self._buf[size:]
    return result

  def size(self):
    return self._eof - 16

  def seek(self, offset, whence=os.SEEK_SET):
    if whence == os.SEEK_END:
      offset = self._eof + offset - 16
    elif whence == os.SEEK_CUR:
      offset = self._file.tell() + offset - 16
    assert offset >= 0
    assert offset <= self._eof - 16
    self._init(offset // 16)
    remaining = offset % 16
    if remaining > 0:
      self._buf = self._decrypt(1)[remaining:]

  def tell(self):
    return self._file.tell() - 16 - len(self._buf)


def convert_tar_entry(entry):
  if args.list:
    print(entry.name)
  if not entry.isfile():
    return (entry, None)
  file = input_tar.extractfile(entry)

  if os.path.normpath(entry.name) == 'backup.json':
    manifest = json.load(file)
    manifest['protected'] = False
    if not args.compressed:
      manifest['compressed'] = False
    manifest = json.dumps(manifest).encode()
    entry.size = len(manifest)
    return (entry, io.BytesIO(manifest))

  if '.tar' in entry.name:
    # Secure Tar, so we need to decrypt.
    file = AesFile(password, file)
    entry.size = file.size()
    if entry.name.endswith('.gz') and not args.compressed:
      # Compressed, so we need to decompress for backup deduplication.
      entry.name = os.path.splitext(entry.name)[0]
      file.seek(-4, os.SEEK_END)
      entry.size = int.from_bytes(file.read(4), 'little')
      file.seek(0)
      file = gzip.GzipFile(mode='r', fileobj=file)
  return (entry, file)


if __name__ == '__main__':
  args = parse_args()
  password = args.password or input('Encryption key: ')
  with tarfile.open(args.input_tar) as input_tar:
    with tarfile.open(args.output_tar ,'w', format=input_tar.format, encoding=input_tar.encoding,
                      pax_headers=input_tar.pax_headers) as output_tar:
      for entry in input_tar:
        output_tar.addfile(*convert_tar_entry(entry))
