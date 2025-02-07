#!/usr/bin/env python3

import argparse
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
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
  parser.add_argument('-i', '--input', metavar='IN_TAR', type=argparse.FileType('rb'),
                      help='encrypted backup archive to decrypt, required', required=True)
  parser.add_argument('-o', '--output', metavar='OUT_TAR', type=argparse.FileType('wb'),
                      help='decrypted backup archive to write, required unless -R is used')
  parser.add_argument('-p', '--password', metavar='KEY',
                      help='encryption key, typically YOUR-ENCR-YPIO-NKEY-FROM-SETT-INGS')
  parser.add_argument('-l', '--list', action='store_true', help='print processed archive entities')
  parser.add_argument('-c', '--compressed', action='store_true',
                      help='do not decompress subarchives')
  parser.add_argument('-D', '--delete', action='store_true',
                      help='remove the input archive after writing the output')
  parser.add_argument('-R', '--replace', action='store_true',
                      help='replace the input archive with the output in the end')

  args = parser.parse_args()
  assert args.output or args.replace, 'Output (-o) or replace mode (-R) must be specified.'
  assert not (args.delete and args.replace), 'Delete (-D) and replace (-R) are exclusive.'
  same = args.output and os.path.samefile(args.input.name, args.output.name)
  assert not same, 'Input (-i) and output (-o) cannot be the same, use replacement (-R) instead.'

  if args.password is None:
    args.password = input('Encryption key: ')
  if not args.output:
    dirname, basename = os.path.split(args.input.name)
    args.output = tempfile.NamedTemporaryFile(prefix=basename + '.tmp', dir=dirname, delete=False)
  return args

# AES-128 encryption as implemented by Secure Tar (https://github.com/pvizeli/securetar).
# - Encryption key is a password hashed 100 times with SHA-256 and cropped to 128 bits.
# - CBC mode is used, so the file is seekable. It's very useful, see below!
# - IV is derived from a seed appended to the key and hashed like the password.
# - IV seed is stored in the first 16 bytes or after a 32-byte header.
# - PKCS7 padding is used at the end.
#
# As of January 2025, Secure Tar also errorneously applies the padding before the last block. This 
# breaks the CRC location in GZIP files. Luckily, we can correctly read the uncompressed size and 
# Tarfile won't cross the EOF and won't trigger the CRC check. But it's a dumpster fire.
class AesFile:
  SECURETAR_MAGIC = b'SecureTar\x02\x00\x00\x00\x00\x00\x00'

  def __init__(self, password, file):
    self._key = AesFile._digest(password.encode())
    self._file = file
    self._start = file.tell()
    header = self._file.read(16)
    if header == AesFile.SECURETAR_MAGIC:
      self.size = int.from_bytes(file.read(8), 'big')
      self._start += 32
    else:
      self.size = file.seek(0, os.SEEK_END) - self._start - 16
      self.seek(-1, os.SEEK_END)
      self.size -= self.read(1)[0]
    self.seek(0)

  def _digest(key):
    for _ in range(100):
      key = hashlib.sha256(key).digest()
    return key[:16]

  def _init(self, block):
    self._file.seek(self._start + block * 16)
    iv = self._file.read(16)
    if block == 0:
      iv = AesFile._digest(self._key + iv)
    self._aes = AES.new(self._key, AES.MODE_CBC, iv)
    self._buf = b''

  def _decrypt(self, blocks):
    return self._aes.decrypt(self._file.read(blocks * 16))

  def read(self, size):
    position = self.tell()
    if position + size > self.size:
      size = self.size - position
    assert size >= 0
    blocks = (size - len(self._buf) + 15) // 16
    assert blocks >= 0
    if blocks > 0:
      self._buf += self._decrypt(blocks)
    result = self._buf[:size]
    self._buf = self._buf[size:]
    return result

  def seek(self, offset, whence=os.SEEK_SET):
    if whence == os.SEEK_END:
      offset += self.size
    elif whence == os.SEEK_CUR:
      offset += self.tell()
    assert offset >= 0
    assert offset <= self.size
    self._init(offset // 16)
    remaining = offset % 16
    if remaining > 0:
      self._buf = self._decrypt(1)[remaining:]

  def tell(self):
    return self._file.tell() - self._start - 16 - len(self._buf)


class TarConverter:
  def __init__(self, input_file):
    self._input_file = input_file

  def __enter__(self):
    self._input_tar = tarfile.open(fileobj=self._input_file)
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self._input_tar.close()

  def extract(self, path):
    found = None
    for info in self._input_tar.getmembers():
      if os.path.normpath(info.name) == path:
        found = info
    if found is None:
      return None
    return self._input_tar.extractfile(info)

  def convert(self, output_file):
    with tarfile.open(fileobj=output_file, mode='w', format=self._input_tar.format,
                      encoding=self._input_tar.encoding,
                      pax_headers=self._input_tar.pax_headers) as output_tar:
      for input_member_info in self._input_tar.getmembers():
        input_member_file = self._input_tar.extractfile(input_member_info)
        for output_member in self.convert_member(input_member_info, input_member_file):
          output_tar.addfile(*output_member)

  def convert_member(self, info, file):
    yield info, file


class OuterTarConverter(TarConverter):
  def __init__(self, args, input_file):
    super().__init__(input_file)
    self._args = args

  def __enter__(self):
    super().__enter__()
    self._manifest = json.load(self.extract('backup.json'))
    assert self._manifest['version'] == 2, 'Only manifest version 2 is supported.'
    if self._manifest['protected']:
      assert self._manifest['crypto'] == 'aes128', 'Only AES-128 encryption is supported.'
    return self

  def convert_member(self, info, file):
    if self._args.list:
      print(info.name)

    if os.path.normpath(info.name) == 'backup.json':
      manifest = json.load(file)
      manifest['protected'] = False
      if not self._args.compressed:
        manifest['compressed'] = False
      manifest = json.dumps(manifest).encode()
      info.size = len(manifest)
      file = io.BytesIO(manifest)
    elif '.tar' in info.name:
      if self._manifest['protected']:
        # Secure Tar, so we need to decrypt.
        file = AesFile(self._args.password, file)
        info.size = file.size
      if info.name.endswith('.gz') and not self._args.compressed:
        # Compressed, so we need to decompress for backup deduplication.
        info.name = os.path.splitext(info.name)[0]
        file.seek(-4, os.SEEK_END)
        info.size = int.from_bytes(file.read(4), 'little')
        file.seek(0)
        file = gzip.GzipFile(mode='r', fileobj=file)
    yield info, file


def main(args):
  with args.input as input, OuterTarConverter(args, input) as outer_tar:
    with args.output as output:
      try:
        outer_tar.convert(output)
      except Exception as error:
        raise RuntimeError('Tar member conversion failed, check the encryption key.') from error
  if args.delete:
    os.remove(args.input.name)
  if args.replace:
    shutil.move(args.output.name, args.input.name)


if __name__ == '__main__':
  main(parse_args())
