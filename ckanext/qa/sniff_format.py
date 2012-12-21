import os
import tempfile
import zipfile

import magic

from ckanext.dgu.lib.formats import Formats

from droid import droid_file_sniffer, DroidError
from old_sniff_format import old_sniff_file_format, is_psv, is_iati, is_xml_but_without_declaration,\
        get_xml_variant, has_rdfa, is_csv, is_json, get_zipped_format

# store global reference so we can take advantage of the caching it does
droid = None
    
def _get_first_part_of_file(filepath, bytes=10000):
    with open(filepath) as f:
         buf = f.read(bytes)
    return buf

def sniff_file_format(filepath, log):
    global droid
    if not droid:
        droid = droid_file_sniffer(log)
    if not droid:
        return old_sniff_file_format(filepath, log)

    format_ = None
    try:
        format_ = droid.sniff_format(filepath)
        log.info("format determined for file %s by DROID: %s" % (filepath, format_["display_name"] if format_ else "Unknown"))

        format_ = refine_droid_result(filepath, format_, log)

        if format_ == Formats.by_extension()['zip']:
            format_ = refine_zipped_format(filepath, log)

    except DroidError, e:
        log.error(e)

    if format_:
        return format_
        
    log.info("Droid failed to fully identify file format, will look at magic")

    magic_format = magic_sniff_format(filepath, log)
    first_part_of_file = _get_first_part_of_file(filepath)

    format_ = refine_magic_result(magic_format, first_part_of_file, log)
    if format_:
        return format_

    log.warn("failed to identify file format via Droid or Magic.")
    return None

def refine_droid_result(filepath, format_, log):
    if format_ == Formats.by_extension()['xml']:
        format_ = get_xml_variant(_get_first_part_of_file(filepath, 500), log)
    if format_ == Formats.by_extension()['html']:
        if has_rdfa(_get_first_part_of_file(filepath, 100000), log):
            format_ = Formats.by_display_name()['RDFa'] 
    return format_

def magic_sniff_format(filepath, log):
    filepath_utf8 = filepath.encode('utf8') if isinstance(filepath, unicode) \
                    else filepath
    magic_format = magic.from_file(filepath_utf8, mime=True)
    log.info("format found by magic %s" % magic_format)
    return magic_format

def refine_magic_result(magic_format, first_part_of_file, log):    
    if magic_format:
        if magic_format == "text/plain": 
            if is_json(first_part_of_file, log):
                return Formats.by_extension()['json']
            if is_csv(first_part_of_file, log):
                return Formats.by_extension()['csv']
            if is_psv(first_part_of_file, log):
                return Formats.by_extension()['psv']
            if is_xml_but_without_declaration(first_part_of_file, log):
                return Formats.by_extension()['xml']

        if magic_format == 'text/html':
            if is_iati(first_part_of_file, log):    
                return Formats.by_display_name()['IATI']
            
        return Formats.by_mime_type()[magic_format]
    return None

class ZipInterpreter(object):
    "this class knows how to find the overall format of a zip file"
    def __init__(self, log):
        self.log = log

    def overall_format(self, formats):
        "for a container format, from the dict of constituent formats, determine overall format"
        format_ = self.highest_scoring_format(formats)
        if format_:
            combined_format =  format_['extension'] + '.zip'
            return Formats.by_extension().get(combined_format)
        return None

    def highest_scoring_format(self, formats):
        scores = [(format_['openness'], format_) for format_ in formats.values() if format_]
        if len(scores) != len(formats): # indicates not all formats are known
            return None
        scores.sort()
        return scores[-1][1]

def refine_zipped_format(filename, log):
    formats = droid.sniff_format_of_zip_contents(filename)
    zip_interpreter = ZipInterpreter(log)
    format_ = zip_interpreter.overall_format(formats)
    if format_:
        return format_

    log.info("droid was unable to indentify all the formats in the zip, will revert to old way")
    #temp_dir = tempfile.mkdtemp()
    #ZipFile(filename).extractall(temp_dir)
    # compile a list of formats of each file
    # determine highest scoring

    return get_zipped_format(filename, log)
    
