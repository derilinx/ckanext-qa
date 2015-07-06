'''Detects character encoding of a resource'''
import re
import os
import subprocess

from ckanext.archiver.model import Status


def detect_encoding_of_an_archived_resource(archival, resource, log):
    '''
    Looks inside a data file\'s contents to determine its character encoding.

    Return values:
      * It returns a tuple: (encoding, comment)
      * If it can work out the encoding then encoding is a string and comment
        is None.
      * If it cannot work out the encoding then encoding is None and a comment
        is provided explaining.
    '''
    if not archival or not archival.cache_filepath:
        comment = 'This file had not been downloaded at the time of checking '\
            'it.'
        return (None, comment)
    # Analyse the cached file
    filepath = archival.cache_filepath
    if not os.path.exists(filepath):
        comment = 'Cache filepath does not exist: "%s".' % filepath
        return (None, comment)
    else:
        if filepath:
            encoding, comment = detect_encoding_of_filepath(filepath, log)
            if encoding:
                return encoding, comment
            else:
                comment = 'The encoding of the file was not recognized from '\
                    'its contents.'
                return (None, comment)
        else:
            # No cache_url
            if archival.status_id == Status.by_text('Chose not to download'):
                comment = 'File was not downloaded deliberately. '\
                    'Reason: %s.' % archival.reason
                return (None, comment)
            elif archival.is_broken is None and archival.status_id:
                # i.e. 'Download failure' or 'System error during archival'
                comment = 'A system error occurred during downloading this '\
                    'file. Reason: %s.' % archival.reason
                return (None, comment)
            else:
                comment = 'This file had not been downloaded at the time of ' \
                    'checking the encoding.'
                return (None, comment)


ENCODINGS = ['ASCII', 'UTF-8', 'Windows-1252']


def detect_encoding_of_filepath(filepath, log):
    encoding = run_bsd_file(filepath, log)
    if encoding:
        comment = 'Detected with BSD "file" utility'
        return encoding, comment
    return None, 'Not able to detect'


def run_bsd_file(filepath, log):
    '''Run the BSD command-line tool "file" to determine file encoding. Returns
    an encoding or None if it fails.'''
    result = check_output(['file', filepath])
    # e.g. "umlaut.windows1252.csv: ISO-8859 text"
    match = re.search(filepath + ': ([^.]+)', result)
    if match:
        encoding = match.groups()[0]
        encoding_map = {'UTF-8 Unicode text': 'ppt',
                        'ASCII text': 'ASCII',
                        }
        encoding = encoding_map.get(encoding, encoding)
        log.info('BSD "file" detected encoding: %s',
                 encoding)
        return encoding
    log.info('"file" could not determine encoding of "%s": %s',
             filepath, result)


# same as the python 2.7 subprocess.check_output
def check_output(*popenargs, **kwargs):
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise Exception('Non-zero exit status %s: %s' % (retcode, output))
    return output
