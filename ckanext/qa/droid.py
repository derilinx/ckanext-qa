import subprocess
import logging
import os
from xml.dom import minidom

from ckanext.dgu.lib.formats import Formats

DROID_INSTALL_DIR = os.path.join(os.path.dirname(__file__), "..", "..",
                        "pyenv-qa", "droid")
DROID_SIGNATURE_FILE = os.path.join(os.path.dirname(__file__), "..", "..",
                        "resources", "DROID_SignatureFile_V65.xml")
DROID_CONTAINER_SIGNATURE_FILE = os.path.join(os.path.dirname(__file__), "..", "..",
                        "resources","container-signature-20120828.xml")

def droid_file_sniffer(log, droid_install_dir=DROID_INSTALL_DIR,
                       signature_file=DROID_SIGNATURE_FILE,
                       container_signature_file=DROID_CONTAINER_SIGNATURE_FILE):
    """This is a factory method for constructing a DroidFileSniffer """
    
    # If Droid is not installed, we can't make one
    if not os.path.exists(DROID_INSTALL_DIR):
        return None
    log = log.getChild('droid')
    droid = DroidWrapper(droid_install_dir, signature_file, 
                            container_signature_file, log)
    signatures = SignatureInterpreter(get_signatures(signature_file), log)
    return DroidFileSniffer(droid, signatures, log)

def pretty_print_formats(formats):
    l = []
    for format_ in sorted(formats):
        l.append(format_["display_name"] if format_ else "Unknown")
    return str(l)

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

    def _follow_softlink(self, filepath):
        "if filepath is a symbolic link, droid will return the real path not the link, so work with the real path"
        if os.path.islink(filepath):
            self.log.debug("found symbolic link, will follow it to find actual file")
            filepath = os.path.realpath(filepath)
        return filepath

    def _run_droid(self, filepath):
        folder = os.path.dirname(filepath)
        results = self.droid.run_droid_on_folder(folder)
        if not results.has_key(filepath):
            raise DroidError("droid didn't find file %s in results, and it should have been in the folder. Only have results:\n%s" % (filepath, results))
        self.results_cache.update(results)

    def puids_of_zip_contents(self, filepath):
        contained_puids = {}
        for key, value in self.results_cache.items():
            # droid results will be of the form "zipfile!/containedfile"
            if filepath + "!/" in key:
                index_of_bang = key.index("!/")
                contained_puids[key[index_of_bang+2:]] = value
        self.log.info("contents of zip file, puids: %s" % sorted(contained_puids.values()))
        return contained_puids

    def puid_of_file(self, filepath):
        filepath = self._follow_softlink(filepath)
        if not self.results_cache.has_key(filepath):
            self._run_droid(filepath)

        original_puid = self.results_cache[filepath]
        return original_puid

    def sniff_format(self, filepath):
        file_puid = self.puid_of_file(filepath)
        if not file_puid:
            return None

        return self.signature_interpreter.determine_format(file_puid)

    def sniff_format_of_zip_contents(self, filepath):
        filepath = self._follow_softlink(filepath)
        if not self.results_cache.has_key(filepath):
            self._run_droid(filepath)

        puids = self.puids_of_zip_contents(filepath)
        formats = self.signature_interpreter.determine_formats(puids)
        return formats

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
                "-Nc", self.container_signature_file,
                "-A", ] # open archives and look in them
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
            raise DroidError("Droid did not give any results. stdout:\n%s\nstderr:\n%s" \
                                % (output, errors))
        return results

class SignatureInterpreter(object):
    """ This class knows how to convert a particular signature to a Format. """

    def __init__(self, signatures, log):
        self._signatures = signatures
        self.log = log

    def determine_formats(self, puids):
        formats = {filename: self.determine_format(puid) 
                        for filename, puid in puids.items()}
        self.log.info("contents of zip file, formats: %s" % pretty_print_formats(formats.values()))
        return formats

    def determine_format(self, puid):
        format_ = None
        signature = self.signature_for_puid(puid)
        if signature:
            self.log.debug("found signature for puid %s:\n%s" % (puid, signature)) 
            format_ = self.format_from_extension(signature) \
                        or self.format_from_other_field(signature)
            
        return format_

    def signature_for_puid(self, puid):
        return self._signatures.get(puid)

    def format_from_extension(self, signature):
        for ext in signature["extensions"]:
            format_ = Formats.by_extension().get(ext)
            if format_:
                return format_
        return None

    def format_from_other_field(self, signature):
        if "Rich Text Format" in signature["display_name"]:
            # Rich Text format is compatible with Word
            return Formats.by_display_name()["DOC"]

        if "Archive" in signature["display_name"] \
                or "ZIP" in signature["display_name"]:
            # not all zip formats use the extension "zip", 
            # but we classify them as zip files anyway
            return Formats.by_extension()["zip"]

        if signature["puid"] == u'fmt/111':
            # OLE2 document of some kind, indicates Microsoft office, 
            # could be a spreadsheet, 
            # but we don't currently know how to determine this, 
            # so we're guessing xls.
            self.log.warn("OLE2 document detected: may contain spreadsheet but may not, giving them benefit of doubt and returning XLS")
            return Formats.by_display_name()["XLS"]

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
