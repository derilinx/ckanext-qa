import re
import csv
import zipfile
import os
from collections import defaultdict
import subprocess
import StringIO

import xlrd
import magic
import messytables
import mimetypes

from ckanext.dgu.lib.formats import Formats

def is_json(buf, log):
    '''Returns whether this text buffer (potentially truncated) is in
    JSON format.'''
    string = '"[^"]*"'
    string_re = re.compile(string)
    number_re = re.compile('-?\d+(\.\d+)?([eE][+-]?\d+)?')
    extra_values_re = re.compile('true|false|null')
    object_start_re = re.compile('{%s:\s?' % string)
    object_middle_re = re.compile('%s:\s?' % string)
    object_end_re = re.compile('}')
    comma_re = re.compile(',\s?')
    array_start_re = re.compile('\[')
    array_end_re = re.compile('\]')
    any_value_regexs = [string_re, number_re, object_start_re, array_start_re, extra_values_re]

    # simplified state machine - just looks at stack of object/array and
    # ignores contents of them, beyond just being simple JSON bits
    pos = 0
    state_stack = [] # stack of 'object', 'array'
    number_of_matches = 0
    while pos < len(buf):
        part_of_buf = buf[pos:]
        if pos == 0:
            potential_matches = (object_start_re, array_start_re, string_re, number_re, extra_values_re)
        elif not state_stack:
            # cannot have content beyond the first byte that is not nested
            return False
        elif state_stack[-1] == 'object':
            # any value
            potential_matches = [comma_re, object_middle_re, object_end_re] + any_value_regexs
        elif state_stack[-1] == 'array':
            # any value or end it
            potential_matches = any_value_regexs + [comma_re, array_end_re]
        for matcher in potential_matches:
            if matcher.match(part_of_buf):
                if matcher in any_value_regexs and state_stack and state_stack[-1] == 'comma':
                    state_stack.pop()
                if matcher == object_start_re:
                    state_stack.append('object')
                elif matcher == array_start_re:
                    state_stack.append('array')
                elif matcher in (object_end_re, array_end_re):
                    try:
                        state = state_stack.pop()
                    except IndexError:
                        # nothing to pop
                        log.info('JSON detect failed: %i matches', number_of_matches)
                        return False
                break
        else:
            # no match
            log.info('JSON detect failed: %i matches', number_of_matches)
            return False
        match_length = matcher.match(part_of_buf).end()
        #print "MATCHED %r %r %s" % (matcher.match(part_of_buf).string[:match_length], matcher.pattern, state_stack)
        pos += match_length
        number_of_matches += 1
        if number_of_matches > 5:
            log.info('JSON detected: %i matches', number_of_matches)
            return True
                                 
    log.info('JSON detected: %i matches', number_of_matches)
    return True

def is_csv(buf, log):
    '''If the buffer is a CSV file then return True.'''
    buf_rows = StringIO.StringIO(buf)
    table_set = messytables.CSVTableSet.from_fileobj(buf_rows)
    return _is_spreadsheet(table_set, 'CSV', log)

def is_psv(buf, log):
    '''If the buffer is a PSV file then return True.'''
    buf_rows = StringIO.StringIO(buf)
    table_set = messytables.CSVTableSet.from_fileobj(buf_rows, delimiter='|')
    return _is_spreadsheet(table_set, 'PSV', log)

def _is_spreadsheet(table_set, format, log):
    def get_cells_per_row(num_cells, num_rows):
        if not num_rows:
            return 0
        return float(num_cells) / float(num_rows)
    num_cells = num_rows = 0
    try:
        table = table_set.tables[0]
        for row in table:
            if row:
                # Must have enough cells
                num_cells += len(row)
                num_rows += 1
                if num_cells > 20 or num_rows > 10:
                    cells_per_row = get_cells_per_row(num_cells, num_rows)
                    # over the long term, 2 columns is the minimum
                    if cells_per_row > 1.9:
                        log.info('Is %s because %.1f cells per row (%i cells, %i rows)', \
                                 format,
                                 get_cells_per_row(num_cells, num_rows),
                                 num_cells, num_rows)
                        return True
    finally:
        pass
    # if file is short then be more lenient
    if num_cells > 3 or num_rows > 1:
        cells_per_row = get_cells_per_row(num_cells, num_rows)
        if cells_per_row > 1.5:
            log.info('Is %s because %.1f cells per row (%i cells, %i rows)', \
                     format,
                     get_cells_per_row(num_cells, num_rows),
                     num_cells, num_rows)
            return True
    log.info('Not %s - not enough valid cells per row '
             '(%i cells, %i rows, %.1f cells per row)', \
             format, num_cells, num_rows, get_cells_per_row(num_cells, num_rows))
    return False
    
def is_html(buf, log):
    '''If this buffer is HTML, return that format type, else None.'''
    xml_re = '.{0,3}\s*(<\?xml[^>]*>\s*)?(<!doctype[^>]*>\s*)?<html[^>]*>'
    match = re.match(xml_re, buf, re.IGNORECASE)
    if match:
        log.info('HTML tag detected')
        return Formats.by_extension()['html']
    log.warning('html not detected %s', buf)    

def is_iati(buf, log):
    '''If this buffer is IATI format, return that format type, else None.'''
    xml_re = '.{0,3}\s*(<\?xml[^>]*>\s*)?(<!doctype[^>]*>\s*)?<iati-(activities|organisations)[^>]*>'
    match = re.match(xml_re, buf, re.IGNORECASE)
    if match:
        log.info('IATI tag detected')
        return Formats.by_extension()['iati']
    #log.warning('IATI not detected %s', buf)

def is_xml_but_without_declaration(buf, log):
    '''Decides if this is a buffer of XML, but missing the usual <?xml ...?>
    tag.'''
    xml_re = '.{0,3}\s*(<\?xml[^>]*>\s*)?(<!doctype[^>]*>\s*)?<([^>\s]*)([^>]*)>'
    match = re.match(xml_re, buf, re.IGNORECASE)
    if match:
        top_level_tag_name, top_level_tag_attributes = match.groups()[-2:]
        if len(top_level_tag_name) > 20 or len(top_level_tag_attributes) > 200:
            log.warning('XML not detected - unlikely length first tag: <%s %s>',
                        top_level_tag_name, top_level_tag_attributes)
            return False
        log.info('XML detected - first tag name: <%s>', top_level_tag_name)
        return True
    log.info('XML tag not detected')
    return False

def get_xml_variant(buf, log):
    '''If this buffer is in a format based on XML, return the format type.'''
    xml_re = '.{0,3}\s*<\?xml[^>]*>\s*(<!doctype[^>]*>\s*)?<([^>\s]*)'
    match = re.match(xml_re, buf, re.IGNORECASE)
    if match:
        top_level_tag_name = match.groups()[-1].lower()
        top_level_tag_name = top_level_tag_name.replace('rdf:rdf', 'rdf')
        top_level_tag_name = top_level_tag_name.replace('wms_capabilities', 'wms')
        if top_level_tag_name in Formats.by_extension():
            format_ = Formats.by_extension()[top_level_tag_name]
            log.info('XML variant detected: %s', format_['display_name'])
            return format_
        log.warning('Did not recognise XML format: %s', top_level_tag_name)
        return Formats.by_extension()['xml']
    log.warning('XML format didn\'t conform to expected format: %s', buf)

def has_rdfa(buf, log):
    '''If the buffer HTML contains RDFa then this returns True'''
    # quick check for the key words
    if 'about=' not in buf or 'property=' not in buf:
        return False

    # more rigorous check for them as tag attributes
    about_re = '<[^>]+\sabout="[^"]+"[^>]*>'
    property_re = '<[^>]+\sproperty="[^"]+"[^>]*>'
    # remove CR to catch tags spanning more than one line
    #buf = re.sub('\r\n', ' ', buf)
    if not re.search(about_re, buf):
        return False
    if not re.search(property_re, buf):
        return False
    log.info('RDFA tags found in HTML')
    return True

