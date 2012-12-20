import subprocess
import os
from xml.dom import minidom

from ckanext.dgu.lib.formats import Formats

#TODO: make this portable!
DROID_INSTALL_DIR = "/home/emily/devtools/droid"
DROID_SIGNATURE_FILE = "/home/emily/.droid6/signature_files/DROID_SignatureFile_V65.xml"
DROID_CONTAINER_SIGNATURE_FILE = "/home/emily/.droid6/container_sigs/container-signature-20120828.xml"

def droid_file_sniffer(log, droid_install_dir=DROID_INSTALL_DIR,
                            signature_file=DROID_SIGNATURE_FILE,
                            container_signature_file=DROID_CONTAINER_SIGNATURE_FILE):
    """This is a factory method for constructing a DroidFileSniffer """
    
    # If Droid is not installed, we can't make one
    if not os.path.exists(DROID_INSTALL_DIR):
        return None
    droid = DroidWrapper(droid_install_dir, signature_file, 
                            container_signature_file, log)
    signatures = SignatureInterpreter(get_signatures(signature_file), log)
    return DroidFileSniffer(droid, signatures, log)

class DroidFileSniffer(object):
    """This class can find what format Droid things a file has, and convert that
    to a Format instance using a SignatureInterpreter class """
    def __init__(self, droid, signature_interpreter, log):
        self.log = log
        self.droid = droid
        self.signature_interpreter = signature_interpreter
        # this cache won't often hit, since most files we sniff are in 
        # different folders
        # but it costs very little and will save a lot of time when it does
        self.results_cache = {}

    def puid_of_file(self, filepath):
        # if it's a symbolic link, droid will return the real path not the link, so work with the real path
        if os.path.islink(filepath):
            self.log.debug("found symbolic link, will follow it to find actual file")
            filepath = os.path.realpath(filepath)

        if self.results_cache.has_key(filepath):
            self.log.info("found cached result for file %s" % filepath) 
            return self.results_cache[filepath]

        folder = os.path.dirname(filepath)
        results = self.droid.run_droid_on_folder(folder)
        self.results_cache.update(results)

        if not results.has_key(filepath):
            raise DroidError("droid didn't find file %s in results, and it should have been in the folder. Only have results:\n%s" % (filepath, results))
        return results.get(filepath)

    def sniff_format(self, filepath):
        puid = self.puid_of_file(filepath)
        if not puid:
            return None
        format_ = self.signature_interpreter.determine_format(puid, filepath)

        return format_

class DroidError(Exception):
    pass

class DroidWrapper(object):
    """This class is responsible for calling the Droid executable and 
        interpreting the results """  
    def __init__(self, droid_install_dir, signature_file,
                    container_signature_file, log):
        self.droid_install_dir = droid_install_dir
        self.signature_file = signature_file
        self.container_signature_file = container_signature_file
        self.log = log
 
    def run_droid_on_folder(self, folder):
        args = ["-Nr", folder,
                "-Ns", self.signature_file,
                "-Nc", self.container_signature_file]
        p = subprocess.Popen(["java", "-Xmx512m", "-jar",
                "%s/droid-command-line-6.1.jar" % self.droid_install_dir]\
                     + args, 
                stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    
        errors = p.stderr.read()
        output = p.stdout.read()
        return self.interpret_droid_output(output, errors)
     
    def interpret_droid_output(self, output, errors):
        results = {}
        for line in output.splitlines():
            fields = line.split(",")
            if len(fields) > 1:
                filename = fields[0]
                puid = fields[1]
                results[filename] = puid
        if not results:
            self.log.error("Droid did not give any results. stdout:\n%s\nstderr:\n%s" % (output, errors))
        return results

class SignatureInterpreter(object):
    """ This class knows how to convert a particular signature to a Format. """

    def __init__(self, signatures, log):
        self._signatures = signatures
        self.log = log

    def determine_format(self, puid, filepath):
        format_ = None
        signature = self.signature_for_puid(puid)
        if signature:
            self.log.debug("found signature for puid %s:\n%s" % (puid, signature)) 
            format_ = self.format_from_signature_extension(puid)
            if not format_:
                format_ = self.determine_Microsoft_format(puid)
            
        return format_

    def signature_for_puid(self, puid):
        return self._signatures.get(puid)

    def format_from_signature_extension(self, puid):
        signature = self.signature_for_puid(puid)
        for ext in signature["extensions"]:
            format_ = Formats.by_extension().get(ext)
            if format_:
                return format_
        return None

    def determine_Microsoft_format(self, puid):
        signature = self.signature_for_puid(puid)
        if "Rich Text Format" in signature["display_name"]:
            # Rich Text format is compatible with Word
            return Formats.by_display_name()["DOC"]

        # OLE2 document of some kind, indicates Microsoft office, could be a spreadsheet.
        if puid in [u'fmt/111']:
            format_ = Formats.by_display_name()["XLS"]
            self.log.info("OLE document: guessed format %s" % format_["display_name"])
            return format_
            # it's some kind of office document, can't tell exactly which
            #return Formats.by_display_name()["DOC"]
        return None


def get_signatures(signature_file):
    """Signatures files are provided by the National Archive
and new versions are regularly released. See:
http://www.nationalarchives.gov.uk/aboutapps/pronom/droid-signature-files.htm
"""
    signatures = {}
    
    dom = minidom.parse(signature_file)
    format_elements = dom.getElementsByTagName("FileFormat")
    for format_ in format_elements:
        extensions = []
        extension_nodes = format_.getElementsByTagName("Extension")
        for node in extension_nodes:
            for child in node.childNodes:
                extensions.append(child.data)
        
        puid = format_.getAttribute("PUID")
        signatures[puid] = {"display_name" : format_.getAttribute("Name"),
                            "mime_type" : format_.getAttribute("MIMEType"),
                            "extensions" : extensions,
                            "puid" : puid}
    return signatures
