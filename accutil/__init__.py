from re import compile as re_compile
from json import dumps, dump, load
from pathlib import Path
from argparse import ArgumentParser
from os import scandir, remove
from hashlib import md5 as _md5
from uuid import uuid4
from configparser import ConfigParser
from os import curdir, environ, fsencode
from os.path import expanduser, join
from multiprocessing.pool import ThreadPool
import logging
from datetime import datetime
from tempfile import TemporaryDirectory

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

from qremiser.blueprint.lib import make_record
import pyqremis

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


def md5(path, buff):
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
            return False
        j = resp.json()
        if j['_self']['identifier'] != acc_id:
            return False
    except:
        return False
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


def split_and_post_record(qremis_record, qremis_api_url):
    try:
        for obj in qremis_record.get_object():
            resp = requests.post(
                qremis_api_url+"object_list", data={"record": dumps(obj.to_dict())}
            )
            if resp.json()['id'] != obj.get_objectIdentifier()[0].get_objectIdentifierValue():
                raise ValueError("problem posting object")
    except KeyError:
        pass

    try:
        for event in qremis_record.get_event():
            resp = requests.post(
                qremis_api_url+"event_list", data={"record": dumps(event.to_dict())}
            )
            if resp.json()['id'] != event.get_eventIdentifier()[0].get_eventIdentifierValue():
                raise ValueError("problem posting event")
    except KeyError:
        pass

    try:
        for relationship in qremis_record.get_relationship():
            resp = requests.post(
                qremis_api_url+"relationship_list", data={"record": dumps(relationship.to_dict())}
            )
            if resp.json()['id'] != relationship.get_relationshipIdentifier()[0].get_relationshipIdentifierValue():
                raise ValueError("problem posting relationship")
    except KeyError:
        pass

    try:
        for rights in qremis_record.get_rights():
            resp = requests.post(
                qremis_api_url+"rights_list", data={"record": dumps(rights.to_dict())}
            )
            if resp.json()['id'] != rights.get_rightsIdentifier()[0].get_rightsIdentifierValue():
                raise ValueError("problem posting rights")
    except KeyError:
        pass

    try:
        for agent in qremis_record.get_agent():
            resp = requests.post(
                qremis_api_url+"agent_list", data={"record": dumps(agent.to_dict())}
            )
            if resp.json()['id'] != agent.get_agentIdentifier()[0].get_agentIdentifierValue():
                raise ValueError("problem posting agent")
    except KeyError:
        pass


def post_file_to_archstor(identifier, fp, archstor_url):
    with open(fp, "rb") as fd:
        payload = {}
        payload['object'] = ('object', fd)
        ingress_post_multipart_encoder = MultipartEncoder(payload)
        resp = requests.put(
            archstor_url+identifier,
            data=ingress_post_multipart_encoder,
            headers={"Content-Type":
                     ingress_post_multipart_encoder.content_type},
            stream=True
        )
        assert(resp.json()['identifier'] == identifier)


def add_objId_to_acc(acc_idnest_url, acc_id, identifier):
    idnest_resp = requests.post(acc_idnest_url+acc_id+"/", data={"member": identifier})
    idnest_resp.raise_for_status()
    assert(idnest_resp.json()['Added'][0]['identifier'] == identifier)


def confirm_remote_copy_matches(identifier, archstor_url, comp_md5, buff):
    # TODO: Intelligently handle removing objects whose fixitys don't match?
    # or maybe reporting a fixity check failure event?
    with TemporaryDirectory() as tmp_dir:
        dl_copy_path = join(tmp_dir, uuid4().hex)
        dl_copy = requests.get(archstor_url+identifier, stream=True)
        dl_copy.raise_for_status()
        with open(dl_copy_path, 'wb') as f:
            for chunk in dl_copy.iter_content(chunk_size=buff):
                f.write(chunk)

        remote_md5 = md5(dl_copy_path, buff)
        if remote_md5 != comp_md5:
            raise RuntimeError("md5 mismatch from remote: {} != {}".format(remote_md5, comp_md5))
    return remote_md5


def secure_incoming_file(path, buffer_location, buff):
    if buffer_location is not None:
        buffered = True
        tmp_path = str(Path(buffer_location, uuid4().hex))
        with open(path, 'rb') as src:
            with open(tmp_path, 'wb') as dst:
                d = src.read(buff)
                while d:
                    dst.write(d)
                    d = src.read(buff)
        buffered_md5 = md5(tmp_path, buff)
        # Tolerate failures on the second read, but emit a warning
        try:
            original_md5 = md5(path, buff)
        except IOError:
            original_md5 = None
        if buffered_md5 != original_md5:
            log.warn("Buffered md5 != original md5! But no read errors reported on original write, continuing...")
        path = Path(tmp_path)
    else:
        buffered = False
        buffered_md5 = None
        original_md5 = md5(path, buff)
    return str(path), original_md5, buffered, buffered_md5


def build_and_post_ingest_event(identifier, qremis_api_url):
    ingest_event = pyqremis.Event(
        pyqremis.EventIdentifier(
            eventIdentifierType="uuid",
            eventIdentifierValue=uuid4().hex
        ),
        pyqremis.EventDetailInformation(
            eventDetail="Ingestion confirmed into the long term storage environment"
        ),
        eventOutcomeInformation=pyqremis.EventOutcomeInformation(
            eventOutcome="success"
        ),
        eventType="ingest",
        eventDateTime=datetime.now().isoformat()
    )

    ingest_relationship = pyqremis.Relationship(
        pyqremis.RelationshipIdentifier(
            relationshipIdentifierType="uuid",
            relationshipIdentifierValue=uuid4().hex
        ),
        pyqremis.LinkingObjectIdentifier(
            linkingObjectIdentifierType="uuid",
            linkingObjectIdentifierValue=identifier
        ),
        pyqremis.LinkingEventIdentifier(
            linkingEventIdentifierType=ingest_event.get_eventIdentifier()[0].get_eventIdentifierType(),
            linkingEventIdentifierValue=ingest_event.get_eventIdentifier()[0].get_eventIdentifierValue()
        ),
        relationshipType="link",
        relationshipSubType="simple",
        relationshipRole="links the object to its original ingest event."
    )
    ingest_qremis_rec = pyqremis.Qremis(ingest_event, ingest_relationship)
    split_and_post_record(ingest_qremis_rec, qremis_api_url)


def build_and_post_ingest_failure_event(identifier, qremis_api_url):
    ingest_event = pyqremis.Event(
        pyqremis.EventIdentifier(
            eventIdentifierType="uuid",
            eventIdentifierValue=uuid4().hex
        ),
        pyqremis.EventDetailInformation(
            eventDetail="Ingestion failed into the long term storage environment"
        ),
        eventOutcomeInformation=pyqremis.EventOutcomeInformation(
            eventOutcome="failure"
        ),
        eventType="ingest",
        eventDateTime=datetime.now().isoformat()
    )

    ingest_relationship = pyqremis.Relationship(
        pyqremis.RelationshipIdentifier(
            relationshipIdentifierType="uuid",
            relationshipIdentifierValue=uuid4().hex
        ),
        pyqremis.LinkingObjectIdentifier(
            linkingObjectIdentifierType="uuid",
            linkingObjectIdentifierValue=identifier
        ),
        pyqremis.LinkingEventIdentifier(
            linkingEventIdentifierType=ingest_event.get_eventIdentifier()[0].get_eventIdentifierType(),
            linkingEventIdentifierValue=ingest_event.get_eventIdentifier()[0].get_eventIdentifierValue()
        ),
        relationshipType="link",
        relationshipSubType="simple",
        relationshipRole="links the object to its original ingest failure event."
    )
    ingest_qremis_rec = pyqremis.Qremis(ingest_event, ingest_relationship)
    split_and_post_record(ingest_qremis_rec, qremis_api_url)


def build_and_post_initial_fixity_check_event(identifier, fixity_md5, qremis_api_url):
    fixity_event = pyqremis.Event(
        pyqremis.EventIdentifier(
            eventIdentifierType="uuid",
            eventIdentifierValue=uuid4().hex
        ),
        pyqremis.EventDetailInformation(
            eventDetail="performed via md5 comparison of remote and local copies"
        ),
        pyqremis.EventDetailInformation(
            eventDetail="computed md5 was: {}".format(fixity_md5)
        ),
        eventOutcomeInformation=pyqremis.EventOutcomeInformation(
            eventOutcome="success"
        ),
        eventType="fixity check",
        eventDateTime=datetime.now().isoformat()
    )

    fixity_relationship = pyqremis.Relationship(
        pyqremis.RelationshipIdentifier(
            relationshipIdentifierType="uuid",
            relationshipIdentifierValue=uuid4().hex
        ),
        pyqremis.LinkingObjectIdentifier(
            linkingObjectIdentifierType="uuid",
            linkingObjectIdentifierValue=identifier
        ),
        pyqremis.LinkingEventIdentifier(
            linkingEventIdentifierType=fixity_event.get_eventIdentifier()[0].get_eventIdentifierType(),
            linkingEventIdentifierValue=fixity_event.get_eventIdentifier()[0].get_eventIdentifierValue()
        ),
        relationshipType="link",
        relationshipSubType="simple",
        relationshipRole="links the object to a fixity check event which took place during original ingest."
    )
    fixity_qremis_rec = pyqremis.Qremis(fixity_event, fixity_relationship)
    split_and_post_record(fixity_qremis_rec, qremis_api_url)


def mint_run_event():
    event = pyqremis.Event(
        pyqremis.EventIdentifier(
            eventIdentifierType="uuid",
            eventIdentifierValue=uuid4().hex
        ),
        pyqremis.EventDetailInformation(
            eventDetail="The ingest run which encompasses individual ingest events"
        ),
        eventType="ingest",
        eventDateTime=datetime.now().isoformat()
    )
    return event


def ingest_file(path, acc_id, buffer_location, buff, root,
                archstor_url, acc_idnest_url, qremis_api_url, run_event,
                confirm=False):

    # TODO: Handle failure at different parts of the accessioning
    # process intelligently, reporting the events via qremis

    output = {}
    objIdentifier = pyqremis.ObjectIdentifier(objectIdentifierType="uuid",
                                              objectIdentifierValue=uuid4().hex)

    output['objectIdentifier'] = objIdentifier.get_objectIdentifierValue()

    try:
        output['filepath'] = sanitize_path(fsencode(path))
        if root is not None:
            output['root'] = sanitize_path(fsencode(root))
        else:
            output['root'] = None
        output['success'] = False
        output['originalName'] = output['filepath'].lstrip(output['root'])
        output['accession_id'] = acc_id

        # If a buffer location is specified, copy the file to there straight
        # away so we don't stress the original media. Then confirm the copy if
        # possible (otherwise emit a warning) and work with that copy from
        # there.
        path, output['orig_md5'], output['buffered'], output['buffered_md5'] = \
            secure_incoming_file(path, buffer_location, buff)

        # TODO: Handle remote qremis generation
        qremis_record = make_record(path, originalName=output['originalName'], objectIdentifier=objIdentifier)
        identifier = qremis_record.get_object()[0].get_objectIdentifier()[0].get_objectIdentifierValue()
        output['object_id'] = identifier

        # POST qremis
        split_and_post_record(qremis_record, qremis_api_url)
        log.debug("qremis POST'd")

        # POST object
        post_file_to_archstor(identifier, path, archstor_url)
        log.debug("Content saved")

        # GET object if confirm
        if confirm:
            fixity_md5 = confirm_remote_copy_matches(
                identifier, archstor_url,
                output['buffered_md5'] if output['buffered_md5'] else output['orig_md5'], buff
            )
            build_and_post_initial_fixity_check_event(identifier, fixity_md5, qremis_api_url)

        # Add objID to Acc
        add_objId_to_acc(acc_idnest_url, acc_id, identifier)

        # Add ingest event to qremis
        build_and_post_ingest_event(identifier, qremis_api_url)
        # Cleanup

        # If we buffered the file into safe storage somewhere in addition to the
        # origin media remove it now
        if buffer_location is not None:
            remove(path)
        output['success'] = True

    except Exception as e:
        try:
            build_and_post_ingest_failure_event(objIdentifier.get_objectIdentifierValue(), qremis_api_url)
        except Exception as e:
            log.critical("An error occured in reporting an error event to the qremis api")
        output['data'] = "{}: {}".format(str(type(e)), str(e))
        output['success'] = False

    run_event_relationship = pyqremis.Relationship(
        pyqremis.RelationshipIdentifier(
            relationshipIdentifierType="uuid",
            relationshipIdentifierValue=uuid4().hex
        ),
        pyqremis.LinkingObjectIdentifier(
            linkingObjectIdentifierType="uuid",
            linkingObjectIdentifierValue=objIdentifier.get_objectIdentifierValue()
        ),
        pyqremis.LinkingEventIdentifier(
            linkingEventIdentifierType=run_event.get_eventIdentifier()[0].get_eventIdentifierType(),
            linkingEventIdentifierValue=run_event.get_eventIdentifier()[0].get_eventIdentifierValue()
        ),
        relationshipType="link",
        relationshipSubType="simple",
        relationshipRole="links the object to its original run event."
    )
    split_and_post_record(pyqremis.Qremis(run_event_relationship), qremis_api_url)
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
            "--buffer_location", help="A location on disk to save " +
            "files briefly* from outside media to operate on. If not " +
            "specified the application will read straight from the outside " +
            "multiple times.", type=str, action='store', default=None
        )
        parser.add_argument(
            "--buff", help="How much data to load into RAM in one go for " +
            "various operations.",
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
            "directory that needs to be accessioned.",
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
            "--receipt_dir", help="A directory to deposit receipt files in.",
            default=None
        )
        parser.add_argument(
            "--qremis_url", help="The URL of the root of the qremis API",
            default=None
        )
        parser.add_argument(
            "--archstor_url", help="The URL of the root of the archstor API",
            default=None
        )
        parser.add_argument(
            "--confirm", help="Redownload all objects after uploading to confirm " +
            "transfer to the object store. Utilizes the buffer location.",
            action='store_true'
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
            self.buff = 1024*8
        log.debug("buff: {}".format(str(self.buff)))

        if args.archstor_url:
            self.archstor_url = args.archstor_url
        elif config["DEFAULT"].get("ARCHSTOR_URL"):
            self.archstor_url = config["DEFAULT"].get("ARCHSTOR_URL")
        else:
            raise ValueError("Archstor url not set")
        log.debug("archstor_url: {}".format(str(self.archstor_url)))

        if args.qremis_url:
            self.qremis_url = args.qremis_url
        elif config["DEFAULT"].get("QREMIS_URL"):
            self.qremis_url = config["DEFAULT"].get("QREMIS_URL")
        else:
            raise RuntimeError("No qremis api url specified via arg or conf")
        log.debug("qremis_url: {}".format(str(self.qremis_url)))

        if args.confirm:
            self.confirm = args.confirm
        elif config["DEFAULT"].getboolean("CONFIRM"):
            self.confirm = config["DEFAULT"].get("CONFIRM")
        else:
            self.confirm = False
        log.debug("confirm: {}".format(str(self.qremis_url)))
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

        # Create a "run" event to link all ingested object records to.
        self.run_event = mint_run_event()
        split_and_post_record(pyqremis.Qremis(self.run_event), self.qremis_url)
        print(self.run_event.get_eventIdentifier()[0].get_eventIdentifierValue())

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

        # Determine if we had any problems
        errors = False
        for x in r:
            if x['success'] != True:
                errors = True
                break
        if errors:
            log.warn('Errors have been detected. Please review your receipt.')
        else:
            log.debug("No errors have been detected")

        # Package up our results, save them to a file in the receipt dir
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
            self.archstor_url,
            self.acc_endpoint,
            self.qremis_url,
            self.run_event,
            confirm=self.confirm
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
