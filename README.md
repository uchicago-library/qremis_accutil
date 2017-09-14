# accutil

v0.0.1

[![Build Status](https://travis-ci.org/bnbalsamo/qremis_accutil.svg?branch=master)](https://travis-ci.org/bnbalsamo/qremis_accutil) [![Coverage Status](https://coveralls.io/repos/github/bnbalsamo/qremis_accutil/badge.svg?branch=master)](https://coveralls.io/github/bnbalsamo/qremis_accutil?branch=master)

The qremis accutil is a utility for performing accessions in the qremis based microservice environment for a digital repository.

## Related Projects

- [qremis](https://github.com/bnbalsamo/qremis): A preservation metadata specification
- [pyqremis](https://github.com/bnbalsamo/pyqremis): A python library for working with qremis
- [qremiser](https://github.com/bnbalsamo/qremiser): A python library/microservice for generating qremis from files
- [qremis_api](https://github.com/bnbalsamo/qremis_api): An API for managing qremis records
- [archstor](https://github.com/bnbalsamo/archstor): A web gateway for unifying object storage technologies
- [idnest](https://github.com/uchicago-library/idnest): An API for nested identifier association.



## Usage

```
$ accession --help
usage: accession [-h] [--buffer_location BUFFER_LOCATION] [--buff BUFF]
                 [--verbosity VERBOSITY] [--resume RESUME]
                 [--source_root SOURCE_ROOT] [--filter_pattern FILTER_PATTERN]
                 [--accessions_url ACCESSIONS_URL] [--receipt_dir RECEIPT_DIR]
                 [--qremis_url QREMIS_URL] [--archstor_url ARCHSTOR_URL]
                 [--confirm]
                 target accession_id

positional arguments:
  target                The file/directory that needs to be ingested.
  accession_id          The identifier of the accession the ingested material
                        belongs to, or 'new' to mint a new accession
                        identifier and apply it

optional arguments:
  -h, --help            show this help message and exit
  --buffer_location BUFFER_LOCATION
                        A location on disk to save files briefly* from outside
                        media to operate on. If not specified the application
                        will read straight from the outside multiple times.
  --buff BUFF           How much data to load into RAM in one go for various
                        operations.
  --verbosity VERBOSITY
                        The verbosity of logs to emit.
  --resume RESUME, -r RESUME
                        Resume a previously started run by specifying
                        receipt(s) which contains errors.
  --source_root SOURCE_ROOT
                        The root of the directory that needs to be
                        accessioned.
  --filter_pattern FILTER_PATTERN
                        Regexes to use to exclude files whose rel paths match.
  --accessions_url ACCESSIONS_URL
                        The url of the accessions idnest.
  --receipt_dir RECEIPT_DIR
                        A directory to deposit receipt files in.
  --qremis_url QREMIS_URL
                        The URL of the root of the qremis API
  --archstor_url ARCHSTOR_URL
                        The URL of the root of the archstor API
  --confirm             Redownload all objects after uploading to confirm
                        transfer to the object store. Utilizes the buffer
                        location.
```
* All URLs should include trailing slashes

# Author
Brian Balsamo <brian@brianbalsamo.com>
