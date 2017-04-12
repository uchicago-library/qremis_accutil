from re import compile as re_compile
from json import dumps, dump, load
from pathlib import Path
from argparse import ArgumentParser
from os import scandir, remove
from hashlib import md5 as _md5
from uuid import uuid4
from configparser import ConfigParser
from os import curdir, environ, fsencode
from os.path import expanduser
from multiprocessing.pool import ThreadPool
import logging
from datetime import datetime
# from random import randint

import requests

from pymongo import MongoClient
from gridfs import GridFS

from qremiser.blueprint.lib import make_record

__author__ = "Brian Balsamo"
__email__ = "balsamo@uchicago.edu"
__publication__ = ""
__version__ = "0.0.1dev"


log = logging.getLogger(__name__)


def launch():
    """
    entry point launch hook
    """
    app = AccUtil()
    app.main()


def rscandir(path="."):
    for entry in scandir(path):
        yield entry
        if entry.is_dir():
            yield from rscandir(entry.path)


def sanitize_path(some_path):
    return bytes(some_path).hex()


def md5(path, buff=1024*1000*8):
    hasher = _md5()
    with open(path, 'rb') as f:
        data = f.read(buff)
        while data:
            hasher.update(data)
            data = f.read(buff)
    return hasher.hexdigest()


def mint_acc(acc_endpoint):
    acc_create_response = requests.post(
        acc_endpoint
    )
    acc_create_response.raise_for_status()
    acc_create_json = acc_create_response.json()
    return acc_create_json['Minted'][0]['identifier']


def check_acc_exists(acc_endpoint, acc_id):
    target_acc_url = acc_endpoint+acc_id + "/"
    try:
        resp = requests.get(target_acc_url)
        if not resp.status_code == 200:
            raise ValueError("Bad response code!")
        j = resp.json()
        if not j['_self']['identifier'] == acc_id:
            raise ValueError("Bad acc identifier!")
    except:
        raise ValueError("Something bad went on confirming the acc exists!")
    return True


def get_config(config_file=None):
    """
    Grab the config CLI --> env var --> typical locations
    """
    config = ConfigParser()
    if config_file:
        config.read(config_file)
        return config
    elif environ.get("ACCUTIL_CONFIG"):
        config.read(environ.get("ACCUTIL_CONFIG"))
        return config
    for x in [
        curdir,
        expanduser("~"),
        str(Path(expanduser("~"), ".config")),
        str(Path(expanduser("~"), ".config", "accutil")),
        "/etc", str(Path("/etc", "accutil"))
    ]:
        if Path(x, "accutil.conf").is_file():
            config.read(str(Path(x, "accutil.conf")))
            return config
    return ConfigParser()


def ingest_file(*args):
    path = args[0]
    acc_id = args[1]
    buffer_location = args[2]
    buff = args[3]
    root = args[4]
    running_buffer_delete = args[5]
    mongo_host = args[6]
    mongo_port = args[7]
    mongo_db_name = args[8]
    acc_idnest_url = args[9]

    _lts_client = MongoClient(mongo_host, mongo_port)
    _lts_db = _lts_client[mongo_db_name]
    LTS_FS = GridFS(_lts_db)

    output = {}
    output['filepath'] = sanitize_path(fsencode(path))
    if root is not None:
        output['root'] = sanitize_path(fsencode(root))
    else:
        output['root'] = None
    output['success'] = False
    output['data'] = None

    try:
        # faking failures for debugging
        # if randint(0, 1) == 0:
        #     msg = "This is a test error!"
        #     log.critical(msg)
        #     raise RuntimeError(msg)
        #  Start building the data dict we're going to throw at the endpoint.
        data = {}
        data['accession_id'] = acc_id
        # Compute our originalName from the path, considering it relative to a
        # root if one was provided
        if root is not None:
            originalName = str(Path(path).relative_to(root))
        else:
            originalName = path
        data['name'] = sanitize_path(fsencode(originalName))

        # If a buffer location is specified, copy the file to there straight
        # away so we don't stress the original media. Then confirm the copy if
        # possible (otherwise emit a warning) and work with that copy from
        # there.
        # TODO: Handling of partial reads?
        precomputed_md5 = None
        if buffer_location is not None:
            tmp_path = str(Path(buffer_location, uuid4().hex))
            with open(path, 'rb') as src:
                with open(tmp_path, 'wb') as dst:
                    d = src.read(buff)
                    while d:
                        dst.write(d)
                        d = src.read(buff)
            precomputed_md5 = md5(tmp_path, buff)
            if not precomputed_md5 == md5(path, buff):
                log.warn("The buffered file's md5 does not equal the origin md5!")
            path = Path(tmp_path)

        # Re-use our hash of the buffer location if we have it precomputed.
        if precomputed_md5:
            data['md5'] = precomputed_md5
        else:
            data['md5'] = md5(path, buff)

        # TODO: Handle remote qremis generation
        qremis_record = make_record(path)
        identifier = qremis_record.get_object()[0].get_objectIdentifier()[0].get_objectIdentifierValue()

        # POST qremis
        pass

        # GET qremis
        pass

        # Compare
        pass

        # POST object
        content_target = LTS_FS.new_file(_id=identifier)
        with open(path, 'rb') as src:
            z = src.read(buff)
            while z:
                content_target.write(z)
                z = src.read(buff)
        content_target.close()
        log.debug("Content saved")

        # GET object? <-- should this be conditional?
        gr_entry = LTS_FS.find_one({"_id": identifier})
        if not gr_entry:
            raise RuntimeError("Couldn't retrieve object")

        # Compare <-- should this be conditional?
        remote_md5 = gr_entry.md5
        if remote_md5 != data['md5']:
            raise RuntimeError("{} != {}".format(remote_md5, data['md5']))

        # Add objID to Acc
        idnest_resp = requests.post(acc_idnest_url+acc_id+"/", data={"member": identifier})
        idnest_resp.raise_for_status()

        # Add ingest event to qremis
        pass

        # Cleanup

        # If we buffered the file into safe storage somewhere in addition to the
        # origin media remove it now
        if buffer_location is not None and running_buffer_delete:
            remove(path)
        output['success'] = True

        # If we redownloaded the file to check its remote storage is secure
        # we remove it now
        pass

        return output

    except Exception as e:
        raise
        output['data'] = "{}: {}".format(str(type(e)), str(e))
    return output


class AccUtil:
    def main(self):
        # Instantiate boilerplate parser
        parser = ArgumentParser()
        parser.add_argument(
            "target", help="The file/directory that " +
            "needs to be ingested.",
            type=str, action='store'
        )
        parser.add_argument(
            "accession_id", help="The identifier of the accession " +
            "the ingested material belongs to, or 'new' to mint a new " +
            "accession identifier and apply it",
            type=str, action='store'
        )
        parser.add_argument(
            "--running_buffer_delete",
            help="If this argument is passed individual files will be " +
            "deleted out of the buffer after they are POST'd to the " +
            "ingress endpoint. If it isn't _you must clean up your " +
            "buffer location manually_. If the location you are addressing " +
            "is bigger than your buffering location, not passing this " +
            "argument can result in your disk being filled.",
            action='store_true', default=None
        )
        parser.add_argument(
            "--buffer_location", help="A location on disk to save " +
            "files briefly* from outside media to operate on. If not " +
            "specified the application will read straight from the outside " +
            "multiple times.", type=str, action='store', default=None
        )
        parser.add_argument(
            "--buff", help="How much data to load into RAM in one go for " +
            "various operations. Currently the maximum for this should be " +
            "~2*n bits in RAM, with n specified in this arg.",
            type=int, action='store', default=None
        )
        parser.add_argument(
            "--verbosity", help="The verbosity of logs to emit.",
            default="INFO"
        )
        parser.add_argument(
            "--resume", "-r", help="Resume a previously " +
            "started run by specifying receipt(s) which contains errors.",
            default=None, action='append'
        )
        parser.add_argument(
            "--source_root", help="The root of the  " +
            "directory that needs to be staged.",
            type=str, action='store',
            default=None
        )
        parser.add_argument(
            "--filter_pattern", help="Regexes to " +
            "use to exclude files whose rel paths match.",
            action='append', default=[]
        )
        parser.add_argument(
            "--accessions_url", help="The url of the accessions idnest.",
            action='store', default=None
        )
        parser.add_argument(
            "--receipt-dir", help="A directory to deposit receipt files in.",
            default=None
        )
        parser.add_argument(
            "--mongo-host",
            default=None
        )
        parser.add_argument(
            "--mongo-port",
            default=None
        )
        parser.add_argument(
            "--mongo-db-name",
            default=None
        )
        # Parse arguments into args namespace
        args = parser.parse_args()

        # App code
        config = get_config()

        # Argument handling

        # ~~ NOTE TO FUTURE SELF ~~
        # The child threads produce logging - file logging must be made thread
        # safe.
        # Maintaining the ability to run multiple instances of the accutil at
        # the same time also mandates making any aggregate logging process safe
        # as well. Some combination of threading.Lock and fasteners should be
        # able to accomplish this.
        # Consider porting parts of the logging infrastructure from toolsuite
        # into just this utility?

        logging.basicConfig(level=args.verbosity)
        target = Path(args.target)
        self.root = args.source_root
        log.debug("Compiling filter patterns...")
        self.filters = [re_compile(x) for x in args.filter_pattern]
        log.debug("Filter patterns compiled")
        self.acc_id = args.accession_id

        if args.accessions_url:
            self.acc_endpoint = args.accessions_url
        elif config["DEFAULT"].get("ACCESSIONS_URL"):
            self.acc_endpoint = config["DEFAULT"].get("ACCESSIONS_URL")
        else:
            msg = "No ingress url specified at CLI or in a conf!"
            log.critical(msg)
            raise RuntimeError(msg)
        log.debug("acc url: {}".format(self.acc_endpoint))

        if args.buffer_location:
            self.buffer_location = args.buffer_location
        elif config["DEFAULT"].get("BUFFER_LOCATION"):
            self.buffer_location = config["DEFAULT"].get("BUFFER_LOCATION")
        else:
            self.buffer_location = None
        log.debug("buffer location: {}".format(str(self.buffer_location)))

        if isinstance(args.running_buffer_delete, bool):
            self.running_buffer_delete = args.running_buffer_delete
        elif isinstance(config["DEFAULT"].getboolean(
                "RUNNING_BUFFER_DELETE"), bool):
            self.running_buffer_delete = config["DEFAULT"].getboolean(
                "RUNNING_BUFFER_DELETE")
        else:
            self.running_buffer_delete = False
        log.debug(
            "running buffer delete: {}".format(str(self.running_buffer_delete))
        )

        if args.receipt_dir:
            self.receipt_dir = args.receipt_dir
        elif config["DEFAULT"].get("RECEIPT_DIR"):
            self.receipt_dir = config["DEFAULT"].get("RECEIPT_DIR")
        else:
            msg = "No receipt dir specificed at CLI or in a conf!"
            log.critical(msg)
            raise RuntimeError(msg)
        log.debug("recept dir: {}".format(str(self.receipt_dir)))
        if not Path(self.receipt_dir).is_dir():
            msg = "Specified receipt dir doesn't exist!"
            log.critical(msg)
            raise RuntimeError(msg)

        if isinstance(args.buff, int):
            self.buff = args.buff
        elif isinstance(config["DEFAULT"].getint("BUFF"), int):
            self.buff = config["DEFAULT"].getint("BUFF")
        else:
            self.buff = 1024*1000*8
        log.debug("buff: {}".format(str(self.buff)))

        if args.mongo_host:
            self.mongo_host = args.mongo_host
        elif config["DEFAULT"].get("MONGO_HOST"):
            self.mongo_host = config["DEFAULT"].get("MONGO_HOST")
        else:
            self.mongo_host = "localhost"
        log.debug("mongo_host: {}".format(str(self.mongo_host)))

        if args.mongo_port:
            self.mongo_port = int(args.mongo_port)
        elif config["DEFAULT"].get("MONGO_PORT"):
            self.mongo_port = int(config["DEFAULT"].get("MONGO_PORT"))
        else:
            self.mongo_port = 27017
        log.debug("mongo_port: {}".format(str(self.mongo_port)))

        if args.mongo_db_name:
            self.mongo_db_name = args.mongo_db_name
        elif config["DEFAULT"].get("MONGO_DB_NAME"):
            self.mongo_db_name = config["DEFAULT"].get("MONGO_DB_NAME")
        else:
            self.mongo_db_name = "lts"
        log.debug("mongo_db_name: {}".format(str(self.mongo_db_name)))

        # Real work

        # If our acc id is given as "new" create a new one, check to be sure it
        # exists regardless and if it doesn't raise an error
        output = {}
        output['acc_minted'] = False
        output['acc_id'] = self.acc_id
        output['file_results'] = []
        if self.acc_id == "new":
            self.acc_id = mint_acc(self.acc_endpoint)
            output['acc_minted'] = True
            output['acc_id'] = self.acc_id
        if not check_acc_exists(self.acc_endpoint, self.acc_id):
            msg = "That acc doesn't exist! " + \
                "(or there was a problem creating a new " + \
                "accession identifier)"
            log.critical(msg)
            raise RuntimeError(msg)
        # Handle ingesting a single file
        if target.is_file():
            log.debug("Target is a file")
            r = self.ingest_file(str(target))
        # Handle ingesting matching files in a dir
        elif target.is_dir():
            log.debug("Target is a dir")
            omit_list = None
            if args.resume:
                omit_list = set()
                for x in args.resume:
                    with open(x) as f:
                        j = load(f)
                    for f_listing in j['file_results']:
                        if f_listing['success'] == True:
                            omit_list.add(f_listing['filepath'])
            r = self.ingest_dir(
                str(target), args.source_root,
                [re_compile(x) for x in args.filter_pattern],
                omit_list
            )
        else:
            msg = "Thats not a file or a dir!"
            log.critical(msg)
            raise ValueError(msg)
        # Make our results a list regardless, for ease of working with them in
        # the receipt context.
        if not isinstance(r, list):
            r = [r]
        errors = False
        for x in r:
            if x['success'] != True:
                errors = True
                break
        if errors:
            log.warn('Errors have been detected. Please review your receipt.')
        else:
            log.debug("No errors have been detected")
        output['file_results'] = r
        receipt_fname = str(Path(self.receipt_dir, datetime.now().isoformat() +
                                 "_" + uuid4().hex + ".json"))
        with open(receipt_fname, 'w') as f:
            dump(output, f, indent=4)
        print("Your receipt is saved on disk at: {}".format(receipt_fname))

    def ingest_file(self, path):
        return ingest_file(
            path, self.acc_id,
            self.buffer_location, self.buff, self.root,
            self.running_buffer_delete, self.mongo_host,
            self.mongo_port, self.mongo_db_name, self.acc_endpoint
        )

    def ingest_dir(self, path, root=None, filters=[], omit_list=None):
        # Enforce filters, delegate to the ingest_file() method
        file_list = set()
        for x in rscandir(path):
            if x.is_file():
                skip = False
                for f in filters:
                    if f.match(x.path):
                        skip = True
                if omit_list and sanitize_path(fsencode(x.path)) in omit_list:
                    skip = True
                if skip:
                    continue
                file_list.add(x.path)

        pool = ThreadPool(50)
        p_result = pool.map(self.ingest_file, file_list)

        return p_result


if __name__ == "__main__":
    launch()
