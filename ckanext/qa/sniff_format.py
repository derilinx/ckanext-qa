import os

import magic

from ckanext.dgu.lib.formats import Formats

from droid import droid_file_sniffer
from old_sniff_format import old_sniff_file_format, is_psv, is_iati, is_xml_but_without_declaration, \
        get_xml_variant, get_zipped_format, has_rdfa, is_csv, is_json

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

    try:
        format_ = droid.sniff_format(filepath)
        log.info("format determined for file %s by DROID: %s" % (filepath, format_["display_name"] if format_ else "Unknown"))

        if format_ == Formats.by_extension()['xml']:
            format_ = get_xml_variant(_get_first_part_of_file(filepath, 500), log)
        if format_ == Formats.by_extension()['html']:
            if has_rdfa(_get_first_part_of_file(filepath, 100000), log):
                format_ = Formats.by_display_name()['RDFa'] 
        if format_ == Formats.by_extension()['zip']:
            format_ = get_zipped_format(filepath, log)

        if format_:
            return format_
            
        log.info("Droid failed to identify file format, will look at mimetypes")

        mimetype = mimetype_from_magic(filepath, log)
        first_part_of_file = _get_first_part_of_file(filepath)

        format_ = detect_format_from_mimetype(mimetype, first_part_of_file, log)
        if format_:
            return format_
        
    except Exception, e:
        log.error(e)

    log.warn("failed to identify file format via Droid or Magic.")
    return None

def mimetype_from_magic(filepath, log):
    filepath_utf8 = filepath.encode('utf8') if isinstance(filepath, unicode) \
                    else filepath
    mimetype = magic.from_file(filepath_utf8, mime=True)
    log.info("mimetype found by magic %s" % mimetype)
    return mimetype

def detect_format_from_mimetype(mimetype, first_part_of_file, log):    
    if mimetype:
        if mimetype == "text/plain": 
            if is_json(first_part_of_file, log):
                return Formats.by_extension()['json']
            if is_csv(first_part_of_file, log):
                return Formats.by_extension()['csv']
            if is_psv(first_part_of_file, log):
                return Formats.by_extension()['psv']
            if is_xml_but_without_declaration(first_part_of_file, log):
                return Formats.by_extension()['xml']

        if mimetype == 'text/html':
            if is_iati(first_part_of_file, log):    
                return Formats.by_display_name()['IATI']
            
        return Formats.by_mime_type()[mimetype]
    return None



