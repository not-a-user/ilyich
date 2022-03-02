Ilyich - Python otrkey decoder
==============================

Multiplatform (Windows, Linux, macOS, *BSD, etc.) Python decoder for
[otrkey-files](https://pyropeter.eu/41yd.de/blog/2010/04/18/otrkey-breaker/trackback/index.html)
from [onlinetvrecorder.com](https://onlinetvrecorder.com/).

Inspired by [otrtool](https://github.com/otrtool/otrtool/).

This is not [pyotr](https://pyotr.readthedocs.io/).

Setup
-----

Install dependencies

```sh
python -m pip install --user pycryptodome
```

Then run [`ilyich.py`](ilyich.py).

Command line reference
----------------------

```
usage: ilyich.py [-h] [-v VERBOSITY] {decode,fetch,import,info,verify} ...

Decode otrkey-files from onlinetvrecorder.com.

positional arguments:
  {decode,fetch,import,info,verify}
                        modes of operation
    decode              decode otrkey-file(s)
    fetch               fetch keyphrase(s) for otrkey-file(s)
    import              import keyphrase cache file in otrtool format
    info                show info on otrkey-file(s)
    verify              verify otrkey-file(s), also verify output file(s) if
                        those are present

options:
  -h, --help            show this help message and exit
  -v VERBOSITY, --verbosity VERBOSITY
                        verbosity, 0 to 2) (default: 0)
```

### Decode

```
usage: ilyich.py decode [-h] [-k KEYPHRASE] [-f] [-c CACHE_FILE] [-e EMAIL]
                        [-p PASSWORD] [-t] [-u] [-d OUTPUT_DIRECTORY]
                        INPUT [INPUT ...]

positional arguments:
  INPUT                 input otrkey-file(s)

options:
  -h, --help            show this help message and exit
  -k KEYPHRASE, --keyphrase KEYPHRASE
                        keyphrase to use (default: None)
  -f, --force           force overwriting of existing output files (default:
                        False)
  -c CACHE_FILE, --cache CACHE_FILE
                        keyphrase cache file (default:
                        ${HOME}/.ilyich_cache.json)
  -e EMAIL, --email EMAIL
                        email to fetch keyphrases from server, overrides
                        ILYICH_EMAIL from environment, queried if not
                        specified (default: None)
  -p PASSWORD, --password PASSWORD
                        password to fetch keyphrases from server, overrides
                        ILYICH_PASSWORD from environment, queried if not
                        specified (default: None)
  -t, --progress        show progress bar (default: False)
  -u, --unlink          delete (unlink) input otrkey-file(s) after successful
                        verification of output files (default: False)
  -d OUTPUT_DIRECTORY, --destdir OUTPUT_DIRECTORY
                        output directory (default: .)
```

### Fetch

```
usage: ilyich.py fetch [-h] [-c CACHE_FILE] [-e EMAIL] [-p PASSWORD]
                       INPUT [INPUT ...]

positional arguments:
  INPUT                 input otrkey-file(s)

options:
  -h, --help            show this help message and exit
  -c CACHE_FILE, --cache CACHE_FILE
                        keyphrase cache file (default:
                        ${HOME}/.ilyich_cache.json)
  -e EMAIL, --email EMAIL
                        email to fetch keyphrases from server, overrides
                        ILYICH_EMAIL from environment, queried if not
                        specified (default: None)
  -p PASSWORD, --password PASSWORD
                        password to fetch keyphrases from server, overrides
                        ILYICH_PASSWORD from environment, queried if not
                        specified (default: None)
```

### Import

```
usage: ilyich.py import [-h] [-o OTRTOOL_CACHE_FILE] [-c CACHE_FILE]

options:
  -h, --help            show this help message and exit
  -o OTRTOOL_CACHE_FILE, --otrtool OTRTOOL_CACHE_FILE
                        keyphrase cache file (otrtool format) (default:
                        ${HOME}/.otrkey_cache)
  -c CACHE_FILE, --cache CACHE_FILE
                        keyphrase cache file (default:
                        ${HOME}/.ilyich_cache.json)
```

### Info

```
usage: ilyich.py info [-h] INPUT [INPUT ...]

positional arguments:
  INPUT       input otrkey-file(s)

options:
  -h, --help  show this help message and exit
```

### Verify

```
usage: ilyich.py verify [-h] [-t] [-u] [-d OUTPUT_DIRECTORY] INPUT [INPUT ...]

positional arguments:
  INPUT                 input otrkey-file(s)

options:
  -h, --help            show this help message and exit
  -t, --progress        show progress bar (default: False)
  -u, --unlink          delete (unlink) input otrkey-file(s) after successful
                        verification of output files (default: False)
  -d OUTPUT_DIRECTORY, --destdir OUTPUT_DIRECTORY
                        output directory (default: .)
```
