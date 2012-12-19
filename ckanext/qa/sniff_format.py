import os

import mimetypes

from ckanext.dgu.lib.formats import Formats

from droid import droid_file_sniffer
from old_sniff_format import old_sniff_file_format, is_psv, is_iati, is_xml_but_without_declaration, \
        get_xml_variant, get_zipped_format, has_rdfa

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

    format_ = droid.sniff_format(filepath)
    log.info("format determined for file %s by DROID: %s" % (filepath, format_["display_name"] if format_ else "Unknown"))

    if format_ == Formats.by_extension()['xml']:
        format_ = get_xml_variant(_get_first_part_of_file(filepath, 500), log)

    if format_ == Formats.by_extension()['html']:
        if has_rdfa(_get_first_part_of_file(filepath, 100000), log):
            format_ = Formats.by_display_name()['RDFa'] 
    
    if format_:
        return format_
        
    log.info("Droid failed to identify file format, will look at mimetypes")

    first_part_of_file = _get_first_part_of_file(filepath)
    format_ = detect_format_from_mimetype(filepath, first_part_of_file, log)
    if format_:
        return format_

    log.info("mimetypes failed to identify file format, will look at contents")
    format_ = detect_format_from_contents(first_part_of_file, log)
        
    return format_

def detect_format_from_mimetype(filepath, first_part_of_file, log):
    mimetype = mimetypes.guess_type(filepath)
    log.info("mimetype found %s" % str(mimetype))
    if mimetype and mimetype[0]:
        if mimetype[0] == "text/plain": 
            if is_xml_but_without_declaration(first_part_of_file, log):
                return Formats.by_extension()['xml']
            else:
                return Formats.by_display_name()['TXT']
        if mimetype[0] == 'application/zip':
            return get_zipped_format(filepath, log)
        return Formats.by_mime_type()[mimetype[0]]
    return None

def detect_format_from_contents(first_part_of_file, log):
    if is_psv(first_part_of_file, log):
        return Formats.by_extension()['psv']
    if is_iati(first_part_of_file, log):    
        return Formats.by_display_name()['IATI']
    return None


