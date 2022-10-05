#!/usr/bin/env python3

# dependencies:
# - pycryptodome

import argparse
import json
import logging

from array import array
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify, Error as BinasciiError
from datetime import datetime, timezone
from getpass import getpass
from hashlib import md5
from itertools import cycle
from os import getenv
from pathlib import Path
from sys import stdout
from textwrap import indent
from urllib.error import URLError
from urllib.parse import parse_qs, urlencode
from urllib.request import Request, urlopen
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes

logger = logging.getLogger('ilyich')

### Protocol parameters ###

# blowfish keysize used in bytes
KEYSIZE = 28

# magic that identifies a file as otrkey
MAGIC = b'OTRKEYFILE'

# all headers are encrypted using this key in ecb mode
HEADER_KEY = b'\xef\x3a\xb2\x9c\xd1\x9f\x0c\xac\x57\x59\xc7\xab\xd1\x2c\xc9\x2b\xa3\xfe\x0a\xfe\xbf\x96\x0d\x63\xfe\xbd\x0f\x45'
assert KEYSIZE == len(HEADER_KEY)

HEADER_SIZE = 512
DATA_OFFSET = len(MAGIC) + HEADER_SIZE

# first block to be encoded in request
# cannot be decrypted by server because we use a random iv
IV_HEADER_BLOCK = b'TCHKVSKY'

# length of hash strings as used by the protocol
HASH_LEN = 48
# length of any valid md5sum hexdigest
MD5_LEN = 32

# header indicating an error response from the server
MESSAGE_INTRO = 'MessageToBePrintedInDecoder'

### connection parameters ###

SCHEME = 'http'
HOST = '185.195.80.111' # last changed 2017
PATH = '/quelle_neu1.php'

USERAGENT = 'Linux-OTR-Decoder/0.4.592' # should work without

### implementation parameters ###

READ_CHUNK_SIZE = 0x100000 # 1 MiB
MAX_RESPONSE_SIZE = 0x1000 # 4 KiB

ENV_EMAIL = 'ILYICH_EMAIL'
ENV_PASSWORD = 'ILYICH_PASSWORD'

### command line interface ###
parser = argparse.ArgumentParser(
    description='Decode otrkey-files from onlinetvrecorder.com.',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument('-v', '--verbosity', type=int, metavar='VERBOSITY', help='verbosity, 0 to 2)', default=0)

subparsers = parser.add_subparsers(help='modes of operation', dest='mode', required=True)

parser_decode = subparsers.add_parser(
    'decode',
    help='decode otrkey-file(s)',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser_decode.add_argument('-k', '--keyphrase', metavar='KEYPHRASE', help='keyphrase to use')
parser_decode.add_argument('-f', '--force', action='store_true', help='force overwriting of existing output files')

parser_fetch = subparsers.add_parser(
    'fetch',
    help='fetch keyphrase(s) for otrkey-file(s)',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)

parser_import = subparsers.add_parser(
    'import',
    help='import keyphrase cache file in otrtool format',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser_import.add_argument('-o', '--otrtool', metavar='OTRTOOL_CACHE_FILE', help='keyphrase cache file (otrtool format)', default=str(Path.home() / '.otrkey_cache'))

parser_info = subparsers.add_parser(
    'info',
    help='show info on otrkey-file(s)',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)

parser_verify = subparsers.add_parser(
    'verify',
    help='verify otrkey-file(s), also verify output file(s) if those are present',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)

for p in parser_decode, parser_import, parser_fetch:
    p.add_argument('-c', '--cache', metavar='CACHE_FILE', help='keyphrase cache file', default=str(Path.home() / '.ilyich_cache.json'))

for p in parser_decode, parser_fetch:
    p.add_argument('-e', '--email', metavar='EMAIL', help=f'email to fetch keyphrases from server, overrides {ENV_EMAIL} from environment, queried if not specified')
    p.add_argument('-p', '--password', metavar='PASSWORD', help=f'password to fetch keyphrases from server, overrides {ENV_PASSWORD} from environment, queried if not specified')

for p in parser_decode, parser_verify:
    p.add_argument('-t', '--progress', action='store_true', help='show progress bar')
    p.add_argument('-u', '--unlink', action='store_true', help='delete (unlink) input otrkey-file(s) after successful verification of output files')
    p.add_argument('-d', '--destdir', metavar='OUTPUT_DIRECTORY', help='output directory', default='.')

for p in parser_decode, parser_fetch, parser_info, parser_verify:
    p.add_argument('input', nargs='+', metavar='INPUT', help='input otrkey-file(s)')

class DecoderError(Exception):
    pass

def check(assertion, message):
    if not assertion:
        raise DecoderError(message)

def parse_qs_unique(bytes):
    map = parse_qs(bytes.decode('ascii'))
    check(all(1 == len(value) for value in map.values()), 'duplicate keys in query string')
    return dict((key, value[0]) for key, value in map.items())

class Header():

    @classmethod
    def check(cls, header):
        check('FN' in header, 'missing FN in header')
        check(0 < len(header['FN']), 'empty FN in header')
        check('FH' in header, 'missing FH in header')
        check(HASH_LEN == len(header['FH']), 'invalid FH in header')
        check('OH' in header, 'missing OH in header')
        check(HASH_LEN == len(header['OH']), 'invalid OH in header')
        check('SZ' in header, 'missing SZ in header')
        check(0 < int(header['SZ']), 'invalid SZ in header')
        return True

    @classmethod
    def parse(cls, bytes):
        header = parse_qs_unique(bytes)
        if 'PD' in header:
            del(header['PD'])
        cls.check(header)
        return header

    def __init__(self, file):
        data = file.read(HEADER_SIZE)
        check(HEADER_SIZE == len(data), 'unexpected end of file in otrkey-file header')
        blowfish = Blowfish.new(HEADER_KEY, Blowfish.MODE_ECB)
        self.header = self.parse(compat(blowfish.decrypt, data))

    def __getitem__(self, key):
        return self.header.__getitem__(key)

    def dump(self, *args, **kwargs):
        json.dump(self.header, *args, **kwargs)

    def get_dict(self):
        return self.header

def digest_from_header(hash):
    assert HASH_LEN == len(hash)
    hexdigest = ''.join(''.join(y for y in x) for x in zip(hash[::3], hash[1::3]))
    assert MD5_LEN == len(hexdigest)
    logger.debug(f'hash from header: {hexdigest}')
    digest = unhexlify(hexdigest)
    assert MD5_LEN // 2 == len(digest)
    return digest

class Cache():

    def __init__(self, path):
        self.path = path
        self.map = {}
        logger.debug(f'loading cache')
        try:
            if self.path.is_file():
                print(f'loading cache from "{self.path}"')
                with self.path.open('r') as input:
                    self.map = json.load(input)
            else:
                logger.info(f'no such file: "{self.path}"')
            logger.debug(f'loaded cache: {self.map}')
        except Exception as e:
            raise DecoderError(f'error loading cache from "{self.path}": {e}')

    def otrtool(self, path):
        try:
            if path.is_file():
                print(f'importing cache from "{path}"')
                with path.open('r') as input:
                    for n, line in enumerate(input):
                        words = tuple(word.strip() for word in line.split())
                        try:
                            check(4 == len(words), 'invalid line in otrtool cache')
                            fh, keyphrase, _, fn = words
                            check(HASH_LEN == len(fh), 'invalid FH in otrtool cache')
                            check(2 * KEYSIZE == len(keyphrase), f'invalid keyphrase in otrtool cache, len = {len(keyphrase)}')
                            self.set(fh, keyphrase, fn)
                        except DecoderError as e:
                            print(f'skipping line {n} from otrtool cache: {e}')
                self.save()
            else:
                raise DecoderError(f'no such file: "{path}"')
        except OSError as e:
            raise DecoderError(f'error importing cache from "{path}": {e}')

    def get(self, fh):
        return self.map[fh]['HP'] if fh in self.map else None

    def set(self, fh, keyphrase, fn='', save=False):
        logger.info(f'adding keyphrase for {fn if fn else fh} to cache')
        self.map[fh] = {'HP': keyphrase, 'FN': fn}
        if save:
            self.save()

    def save(self):
        logger.debug(f'saving cache: {self.map}')
        print(f'saving cache to "{self.path}"')
        try:
            with self.path.open('w') as output:
                json.dump(self.map, output, indent=4)
                print('', file=output)
        except Exception as e:
            raise DecoderError(f'error saving cache to "{self.path}": {e}')

def get_file_md5(file, expected):
    total_read = 0
    file_md5 = md5()
    with Progress(expected) as progress:
        while True:
            data = file.read(READ_CHUNK_SIZE)
            file_md5.update(data)
            read = len(data)
            total_read += read
            progress.update(total_read)
            if 0 == read:
                return file_md5, total_read

def get_bytes_md5(bytes):
    bytes_md5 = md5()
    bytes_md5.update(bytes)
    return bytes_md5

no_quote = lambda c, *_: c

def fetch_keyphrase_from_server(header, credentials):
    date = datetime.now(timezone.utc).strftime('%Y%m%d')
    assert 8 == len(date)
    logger.debug(f'date = {date}')

    code = ('&' + urlencode(dict(
        OS = '01677e4c0ae5468b9b8b823487f14524',
        M  = '01677e4c0ae5468b9b8b823487f14524',
        LN = 'DE',
        VN = '1.4.1132',
        IR = 'TRUE',
        IK = 'aFzW1tL7nP9vXd8yUfB5kLoSyATQ',
        FN = header['FN'],
        OH = header['OH'],
        A  = credentials.get_email(),
        P  = credentials.get_password(),
        D  = 'd' * 512
    ), quote_via=no_quote))[:512]
    logger.debug(f'plain code = {code}')

    mailhash = get_bytes_md5(credentials.get_email().encode('ascii')).hexdigest()[:32]
    passhash = get_bytes_md5(credentials.get_password().encode('ascii')).hexdigest()[:32]
    bigkey = (
        mailhash[0:13] +
        date[0:4] +
        passhash[0:11] +
        date[4:6] +
        mailhash[21:32] +
        date[6:8] +
        passhash[19:32]
    )
    assert KEYSIZE * 2 == len(bigkey)
    logger.debug(f'bigkey = {bigkey}')
    bigkey = unhexlify(bigkey)

    code = compat(Blowfish.new(bigkey, Blowfish.MODE_CBC, get_random_bytes(8)).encrypt, IV_HEADER_BLOCK + code.encode('ascii'))
    logger.debug(f'encoded code = {hexlify(code)}')

    uri = f'{SCHEME}://{HOST}{PATH}?' + urlencode(dict(
        code = b64encode(code).decode('ascii'),
        AA   = credentials.get_email(),
        ZZ   = date
    ), quote_via=no_quote)
    logger.debug(f'uri = {uri}')

    try:
        with urlopen(Request(url=uri, data=None, headers={'User-Agent': USERAGENT})) as response:
            logger.debug(f'server responded: url = {response.url}, status = {response.status}, headers = {dict(response.headers.items())}')
            if 'Content-Length' in response.headers:
                cl = response.headers['Content-Length']
                try:
                    cl = int(cl)
                except ValueError as e:
                    raise DecoderError(f'bad Content-Length from server: {e}')
                check(MAX_RESPONSE_SIZE >= cl, f'max server response size ({MAX_RESPONSE_SIZE}) exceeded: {cl}')
                data = response.read(cl)
                check(cl == len(data), f'incomplete data from server, announced {cl}, got {len(data)}')
            else:
                data = response.read(MAX_RESPONSE_SIZE + 1)
                check(MAX_RESPONSE_SIZE >= len(data), 'max server response size exceeded')
            logger.debug(f'raw response = {data}')

            try:
                data = data.decode('cp1252')
            except UnicodeDecodeError as e:
                raise DecoderError(f'server response is not cp1252 encoded: {e}')

            if data.startswith(MESSAGE_INTRO):
                print(f'error message from server:\n{indent(data[len(MESSAGE_INTRO):], "| ", lambda _: True)}')
                raise DecoderError('server returned error message')
            try:
                data = b64decode(data, validate=True)
            except BinasciiError as e:
                raise DecoderError(f'server response must be base64 encoded: {e}')
            # logger.debug(f'encoded response = {data}')
            check(0 == len(data) % 8, f'invalid server response, size is {len(data)}')
            data = compat(Blowfish.new(bigkey, Blowfish.MODE_CBC, b'\0' * 8).decrypt, data)
            logger.debug(f'decoded response = {data}')
            check(8 <= len(data), 'server response too short')
            data = parse_qs_unique(data[8:]) # discard IV
            logger.debug(f'parsed response = {data}')
            for p in 'D', 'A', 'P', 'HP':
                check(p in data, f'missing parameter {p} in server response')
            check(credentials.get_email() == data['A'], f'unexpected email in server response: {data["A"]}')
            check(credentials.get_password() == data['P'], f'unexpected password in server response: {data["P"]}')
            keyphrase = data['HP']
            check(KEYSIZE * 2 == len(keyphrase), f'invalid keyphrase in server response, length is {len(keyphrase)}')
            return keyphrase
    except URLError as e:
        raise DecoderError(f'error contacting server at {SCHEME}://{HOST}: {e}')

def compat(operation, data):
    'blowfish-compat mode means bytes swapped, see https://github.com/winlibs/libmcrypt/blob/master/modules/algorithms/blowfish-compat.c'
    assert 0 == len(data) % 4
    data = array('I', data)
    data.byteswap()
    data = array('I', operation(data.tobytes()))
    data.byteswap()
    return data.tobytes()

def exists(path):
    try:
        return path.exists()
    except OSError as e:
        logger.warning(f'error checking for file "{path}": {e}')
        return False

class Progress():

    def __init__(self, total, length=40, file=stdout):
        self.total = total
        self.length = length
        self.file = file
        self.spinner = cycle('🌑🌒🌓🌔🌕🌖🌗🌘')

    def bar(self, current):
        done = (self.length * current) // self.total
        assert 0 <= done <= self.length, 'progress screwed'
        return '[' + '=' * done + ' ' * (self.length - done) + ']'
    
    def __enter__(self):
        if 0 < self.total:
            print('\r', end='', file=self.file)
            self.file.flush()
        self.update(0)
        return self
    
    def __exit__(self, *_):
        if 0 < self.total:
            print('', file=self.file)
            self.file.flush()
    
    def update(self, current):
        if 0 < self.total:
            print(f'\r{self.bar(current)} {next(self.spinner)} {current >> 20}/{self.total >> 20} MiB', end='', file=self.file)
            self.file.flush()

class File():

    def __init__(self, path):
        self.path = path
        try:
            self.file = self.path.open('rb')
        except OSError as e:
            raise DecoderError(f'error opening otrkey-file "{self.path}" for reading: {e}')
        self.check_magic()
        self.header = Header(self.file)
        logger.debug(f'header = {self.header.get_dict()}')

    def __enter__(self):
        return self

    def close(self):
        if not None is self.file:
            self.file.close()
            self.file = None

    def __exit__(self, *_):
        self.close()

    def check_magic(self):
        magic = self.file.read(len(MAGIC))
        check(MAGIC == magic, f'not an otrkey-file, magic = {magic}, expected {MAGIC}')

    def print_info(self):
        self.header.dump(stdout, indent=4)
        print()

    def check_hash(self, md5, header_value, name):
        logger.debug(f'{name}: {md5.hexdigest()}')
        check(digest_from_header(header_value) == md5.digest(), f'{name} does not match')
        logger.info(f'{name} matches')
        return True

    def check_input_hash(self, md5):
        self.check_hash(md5, self.header['OH'], 'input hash')

    def check_output_hash(self, md5):
        self.check_hash(md5, self.header['FH'], 'output hash')

    def unlink(self):
        print(f'deleting otrkey-file "{self.path}"')
        self.close()
        try:
            self.path.unlink()
        except Exception as e:
            logger.warning(f'deleting otrkey-file "{self.path}" failed: {e}')

    def fetch_keyphrase(self, credentials):
        print(f'fetching keyphrase for otrkey-file "{self.path}" from server')
        assert isinstance(credentials, Credentials)
        check(not None is credentials.get_email(), 'no EMAIL specified')
        check(not None is credentials.get_password(), 'no PASSWORD specified')
        keyphrase = fetch_keyphrase_from_server(self.header, credentials)
        check(not None is keyphrase, f'failed to fetch keyphrase for {self.header["FH"]} from server')
        logger.info(f'fetched keyphrase for {self.header["FH"]} from server')
        return keyphrase

    def fetch(self, cache, credentials):
        keyphrase = self.fetch_keyphrase(credentials)
        assert not None is keyphrase
        cache.set(self.header['FH'], keyphrase, self.header['FN'], save=True)

    def decode(self, destdir, cache, c_or_k, force, unlink, show_progress):
        path = destdir / Path(self.header['FN'])
        check(force or not exists(path), f'output file "{path}" exists, skipping')

        setkey = False

        if isinstance(c_or_k, Credentials):
            keyphrase = cache.get(self.header['FH'])
            if None is keyphrase:
                logger.info(f'no keyphrase in cache for {self.header["FH"]}')
                keyphrase = self.fetch_keyphrase(c_or_k)
                assert not None is keyphrase
                setkey = True
            else:
                print(f'using keyphrase from cache for otrkey-file "{self.path}"')
                logger.info(f'using keyphrase from cache for {self.header["FH"]}')
        else:
            keyphrase = c_or_k
            assert not None is keyphrase
            logger.info(f'using supplied keyphrase for {self.header["FH"]}')
            setkey = True

        check(KEYSIZE * 2 == len(keyphrase), f'keyphrase has wrong length, len = {len(keyphrase)}, expected {KEYSIZE * 2}')
        try:
            binary_keyphrase = unhexlify(keyphrase)
        except BinasciiError as e:
            raise DecoderError(f'invalid keyphrase: {e}')
        blowfish = Blowfish.new(binary_keyphrase, Blowfish.MODE_ECB)

        total_read = 0
        input_md5 = md5()
        output_md5 = md5()
        may_delete_output = False
        try:
            try:
                print(f'decoding otrkey-file "{self.path}"')
                sz = int(self.header['SZ'])
                check(sz > DATA_OFFSET, f'output size specified in otrkey-file "{self.path}" is too small, SZ = {sz}, must be greater than {DATA_OFFSET}')
                with Progress(sz - DATA_OFFSET if show_progress else 0) as progress:
                    with open(path, 'wb') as output:
                        may_delete_output = True
                        while True:
                            data = self.file.read(READ_CHUNK_SIZE)
                            input_md5.update(data)
                            read = len(data)
                            total_read += read
                            check(sz >= total_read + DATA_OFFSET, f'otrkey-file "{self.path}" is too large, read {total_read + DATA_OFFSET}, expected {sz}')
                            progress.update(total_read)
                            if 0 == read:
                                break
                            overhead = read % 8
                            if 0 < overhead:
                                data, overhead_data = data[:-overhead], data[-overhead:]
                            else:
                                overhead_data = b''
                            data = compat(blowfish.decrypt, data) + overhead_data
                            output_md5.update(data)
                            check(len(data) == output.write(data), f'write to "{path}" failed')
                        check(sz == total_read + DATA_OFFSET, f'unexpected end of file in otrkey-file "{self.path}"')
            except OSError as e:
                raise DecoderError(f'error writing output file "{path}": {e}')
            self.check_input_hash(input_md5)
            self.check_output_hash(output_md5)
            print(f'decoding complete for output file "{path}"')
            if setkey:
                cache.set(self.header['FH'], keyphrase, self.header['FN'], save=True)
        except DecoderError as e:
            if may_delete_output:
                logger.info(f'decoding failed, deleting corrupted output file "{path}"')
                try:
                    path.unlink()
                except Exception as e:
                    logger.warning(f'deleting corrupted output file "{path}" failed: {e}')
            raise DecoderError(f'decoding failed: {e}')

        if unlink:
            self.unlink()

    def verify(self, destdir, unlink, show_progress):
        print(f'checking hash for otrkey-file "{self.path}"')
        sz = int(self.header['SZ'])
        check(sz > DATA_OFFSET, f'output size specified in otrkey-file "{self.path}" is too small, SZ = {sz}, must be greater than {DATA_OFFSET}')
        input_md5, read = get_file_md5(self.file, sz - DATA_OFFSET if show_progress else 0)
        check(sz == read + DATA_OFFSET, f'unexpected size of otrkey-file "{self.path}", read {read + DATA_OFFSET}, expected {sz}')
        self.check_input_hash(input_md5)
        print(f'hash matches for otrkey-file "{self.path}"')
        path = destdir / Path(self.header['FN'])
        if exists(path):
            try:
                with path.open('rb') as output:
                    print(f'checking hash for output file "{path}"')
                    output_md5, read = get_file_md5(output, sz - DATA_OFFSET if show_progress else 0)
                    check(sz == read + DATA_OFFSET, f'unexpected size of output file "{path}", read {read}, expected {sz - DATA_OFFSET}')
                    self.check_output_hash(output_md5)
                    print(f'hash matches for output file "{path}"')
                    if unlink:
                        self.unlink()
            except OSError as e:
                raise DecoderError(f'error reading output file "{path}": {e}')
        else:
            print(f'output file "{path}" does not exists, not verifying')

def check_args(args):
    def check_ascii(value, meta):
        if not None is value:
            try:
                value.encode('ascii')
            except UnicodeEncodeError as e:
                raise DecoderError(f'{meta} is not ascii: {e}')
    if args.mode in ('decode', 'fetch'):
        check_ascii(args.email, 'EMAIL')
        check_ascii(args.password, 'PASSWORD')
    if 'decode' == args.mode:
        check_ascii(args.keyphrase, 'KEYPHRASE')

class Credentials():

    def __init__(self, email, password):
        self._email = email
        self._password = password
    
    def get_email(self):
        if not self._email:
            self._email = getenv(ENV_EMAIL)
        try:
            while not self._email:
                self._email = input('email: ')
        except (KeyboardInterrupt, EOFError):
            print()
            raise exit(1)
        return self._email
    
    def get_password(self):
        if not self._password:
            self._password = getenv(ENV_PASSWORD)
        try:
            while not self._password:
                self._password = getpass('password: ')
        except (KeyboardInterrupt, EOFError):
            print()
            raise exit(1)
        return self._password

def main(args):
    logging_level = (
        logging.DEBUG if args.verbosity > 1 else
        logging.INFO if args.verbosity > 0 else
        logging.WARNING
    )
    logger.setLevel(logging_level)
    handler = logging.StreamHandler()
    handler.setLevel(logging_level)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    exit_status = 0

    try:
        check_args(args)
        if 'decode' == args.mode:
            if None is args.keyphrase:
                c_or_k = Credentials(args.email, args.password)
            else:
                check(1 == len(args.input), 'only one input otrkey-file can be decoded using a specific KEYPHRASE')
                check(None is args.email, 'no EMAIL required if KEYPHRASE specified')
                check(None is args.password, 'no PASSWORD required if KEYPHRASE specified')
                c_or_k = args.keyphrase
            cache = Cache(Path(args.cache))
            for path in args.input:
                try:
                    with File(Path(path)) as file:
                        file.decode(args.destdir, cache, c_or_k, args.force, args.unlink, args.progress)
                except DecoderError as e:
                    logger.error(f'error decoding otrkey-file "{path}": {e}')
                    exit_status = 1
        elif 'fetch' == args.mode:
            cache = Cache(Path(args.cache))
            credentials = Credentials(args.email, args.password)
            for path in args.input:
                try:
                    with File(Path(path)) as file:
                        file.fetch(cache, credentials)
                except DecoderError as e:
                    logger.error(f'error fetching keyphrase for otrkey-file "{path}": {e}')
                    exit_status = 1
        elif 'import' == args.mode:
            cache = Cache(Path(args.cache))
            cache.otrtool(Path(args.otrtool))
        elif 'info' == args.mode:
            for path in args.input:
                try:
                    with File(Path(path)) as file:
                        file.print_info()
                except DecoderError as e:
                    logger.error(f'error getting information from otrkey-file "{path}": {e}')
                    exit_status = 1
        elif 'verify' == args.mode:
            for path in args.input:
                try:
                    with File(Path(path)) as file:
                        file.verify(args.destdir, args.unlink, args.progress)
                except DecoderError as e:
                    logger.error(f'error verifying otrkey-file "{path}": {e}')
                    exit_status = 1
        else:
            check(False, 'error decoding command line')
    except DecoderError as e:
        logger.error(f'decoder error: {e}')
        exit_status = 1

    return exit_status

if '__main__' == __name__:
    exit(main(parser.parse_args()))
