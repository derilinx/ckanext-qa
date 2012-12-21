import os
import tempfile
import zipfile

import magic

from ckanext.dgu.lib.formats import Formats

from droid import droid_file_sniffer, DroidError, pretty_print_formats
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
        raise DroidError("droid does not appear to be installed")

    format_ = sniff_format_with_droid(filepath, log)
    if format_:
        return format_
        
    log.info("Droid failed to identify file format, will try using magic")

    format_ = sniff_format_with_magic(filepath, log)
    if format_:
        return format_

    log.warn("failed to identify file format using Droid or Magic.")
    return None

def sniff_format_with_droid(filepath, log):
    format_ = None
    try:
        format_ = droid.sniff_format(filepath)
        log.info("format initially determined for file %s by DROID: %s" % (filepath, format_["display_name"] if format_ else "Unknown"))
        format_ = _refine_droid_result(filepath, format_, log)

    except DroidError, e:
        log.error(e)

    return format_

def _refine_droid_result(filepath, format_, log):
    if format_ == Formats.by_extension()['xml']:
        format_ = get_xml_variant(_get_first_part_of_file(filepath, 500), log)
    if format_ == Formats.by_extension()['html']:
        if has_rdfa(_get_first_part_of_file(filepath, 100000), log):
            format_ = Formats.by_display_name()['RDFa'] 
    if format_ == Formats.by_extension()['zip']:
        format_ = refine_zipped_format(filepath, log)
    return format_

def sniff_format_with_magic(filepath, log):
    filepath_utf8 = filepath.encode('utf8') if isinstance(filepath, unicode) \
                    else filepath
    magic_format = magic.from_file(filepath_utf8, mime=True)
    if not magic_format:
        return None
    first_part_of_file = _get_first_part_of_file(filepath)
    format_ = _refine_magic_result(magic_format, first_part_of_file, log)
    log.info("format found by magic %s" % magic_format)
    return format_

def _refine_magic_result(magic_format, first_part_of_file, log):    
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
        
    return Formats.by_mime_type().get(magic_format)

ZIP_FORMAT = Formats.by_extension()['zip']
        
class ZipSniffer(object):
    "this class knows how to find the overall format of a zip file using Droid and Magic"
    def __init__(self, filepath, droid, log):
        self.filepath = filepath
        self.droid = droid
        self.log = log
        
    def overall_format(self):
        formats = self.droid.sniff_format_of_zip_contents(self.filepath)
        unknown_formats = [relpath for relpath, format_ in formats.items()
                                      if not format_]
        if unknown_formats:
            self.log.info("droid was not able to determine all the contents of the zip. Using magic to find the remainder")
            temp_dir = self.unzip_file()
            found_formats = self.use_magic_to_find_formats(temp_dir, unknown_formats)
            self.log.info("contents of zip file, formats found by magic: %s" % pretty_print_formats(found_formats.values()))
            formats.update(found_formats)
        return overall_format(formats, self.log)

    def use_magic_to_find_formats(self, unzipped_file_location, unknown_formats):
        formats = {}
        for relative_filepath in unknown_formats:
            full_filepath = os.path.join(unzipped_file_location, relative_filepath)
            if not os.path.exists(full_filepath):
                raise DroidError("Droid found a file in the zip which wasn't there when we unzipped it %s" % relative_filepath)
            format_ = sniff_format_with_magic(full_filepath, self.log)
            formats[relative_filepath] = format_
        return formats

    def unzip_file(self):
        zip_ = zipfile.ZipFile(self.filepath, 'r')
        temp_dir = tempfile.mkdtemp()
        zip_.extractall(temp_dir)
        return temp_dir

def overall_format(formats, log):
    """find the highest scoring of these formats, 
    or the zip format itself, and return that"""
    format_ = highest_scoring_format(formats, log)
    if format_:
        log.info("highest scoring format in zip is %s" % format_["display_name"])
        combined_format =  format_['extension'] + '.zip'
        return Formats.by_extension().get(combined_format) or ZIP_FORMAT
    return None

def highest_scoring_format(formats, log):
    formats = formats.values()
    occurrences = {format_['display_name']: formats.count(format_) 
                        for format_ in formats if format_}
    scores = [(format_['openness'], 
               occurrences[format_['display_name']], 
               format_) 
                        for format_ in formats if format_]
    if not scores:
        return None    
    scores.sort()
    highest_score = scores[-1]
    return highest_score[2]

def refine_zipped_format(filename, log):
    zip_sniffer = ZipSniffer(filename, droid, log)
    format_ = zip_sniffer.overall_format()
    if not format_:
        log.warn("Unable to indentify all the formats in the zip, returning generic Zip format")
    return format_ or ZIP_FORMAT

