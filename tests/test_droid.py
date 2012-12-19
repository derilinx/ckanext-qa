import logging
import os
from nose.tools import raises, assert_equal

from ckanext.dgu.lib.formats import Formats
from ckanext.qa.droid import get_signatures, droid_file_sniffer, \
        SignatureInterpreter, DroidFileSniffer, \
        DROID_INSTALL_DIR, \
        DROID_SIGNATURE_FILE, DROID_CONTAINER_SIGNATURE_FILE

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('droid')

def check_for_droid_installation(func):
    from nose.plugins.skip import SkipTest
    def _(*args, **kwargs):
        if not os.path.exists(DROID_SIGNATURE_FILE) \
            or not os.path.exists(DROID_INSTALL_DIR) \
            or not os.path.exists(DROID_CONTAINER_SIGNATURE_FILE):
            raise SkipTest("Test %s is skipped because Droid is not installed" % 
                                func.__name__)
        func(*args, **kwargs)
    _.__name__ = func.__name__
    return _


class TestDroidIntegration(object):

    @check_for_droid_installation
    def test_format_from_puid(self):
        signatures = get_signatures(DROID_SIGNATURE_FILE)
        signature_interpreter = SignatureInterpreter(signatures, log)
        puid = "fmt/215"
        format_ = signature_interpreter.determine_format(puid, "foo.ppt")
        assert_equal (Formats.by_display_name()['PPT'], format_)

    @check_for_droid_installation
    def test_ambiguous_puids(self):
        """This test is to check the signature file is compatible with the 
            Formats.py module. It shouldn't fail unless we update the signature file,
            and only then if there arise ambiguous signatures which match to more 
            than one Format. 
        """
        format_extensions = Formats.by_extension()
        for puid, signature in get_signatures(DROID_SIGNATURE_FILE).items():
            formats = set()
            for ext in signature["extensions"]:
                format_ = format_extensions.get(ext)
                if format_:
                    formats.add(format_["display_name"])
            assert len(formats) in (0, 1), "puid has %s ambiguous extensions %s, found formats %s" % (puid, signature, formats)

    @check_for_droid_installation
    def test_find_puid_of_file(self):
        droid = droid_file_sniffer(log)
        fixture_data_dir = os.path.join(os.path.dirname(__file__), 'data')
        
        signature = droid.puid_of_file(os.path.join(fixture_data_dir, "August-2010.xls"))
        assert_equal("fmt/56", signature)

class TestSignatureInterpreter(object):

    def test_format_from_puid_with_multiple_extensions(self):
        droid = SignatureInterpreter({u'fmt/56': 
                    {'extensions': [u'xlc', u'xlm', u'xls'], 
                     'puid': u'fmt/56', 
                     'display_name': u'Microsoft Excel 3.0 Worksheet (xls)',
                     'extension': u'xlc', 
                     'mime_type': u'application/vnd.ms-excel'}}, log)
        format_ = droid.format_from_signature_extension(u'fmt/56')
        assert_equal(Formats.by_display_name()['XLS'], format_)

    def test_format_from_xlsx(self):
        droid = SignatureInterpreter({u'fmt/111':
                        {'extensions': [],
                         'puid': u'fmt/111',
                         'display_name': u'OLE2 Compound Document Format', 
                         'mime_type': ''}}, log)
        format_ = droid.format_from_signature_extension(u'fmt/111')
        assert_equal(None, format_)


    def test_signature_interpreter_returns_none_with_missing_signature(self):
        signature_interpreter = SignatureInterpreter({}, log)
        assert_equal(None, signature_interpreter.determine_format("foo", "foo"))

    def test_sniff_format_ole_with_xlsx_extension_in_filename(self):
        signature_interpreter = SignatureInterpreter({u'fmt/111':
                        {'extensions': [],
                         'puid': u'fmt/111',
                         'display_name': u'OLE2 Compound Document Format', 
                         'mime_type': ''}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/111', "foo.xlsx")
        assert_equal('XLS', format_["display_name"])

    def test_sniff_format_ole_with_no_clue_in_extension(self):
        signature_interpreter = SignatureInterpreter({u'fmt/111':
                        {'extensions': [],
                         'puid': u'fmt/111',
                         'display_name': u'OLE2 Compound Document Format', 
                         'mime_type': ''}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/111', "foo.bar")
        assert_equal('DOC', format_["display_name"])

    def test_sniff_microsoft(self):
        signature_interpreter = SignatureInterpreter({u'fmt/220':
                        {'extensions': [u'wks'], 
                         'puid': u'fmt/220', 
                         'display_name': 
                        u'Microsoft Works Spreadsheet for Windows', 
                         'mime_type': ''}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/220', "foo.wks")
        assert_equal('XLS', format_["display_name"])

    def test_sniff_rtf(self):
        signature_interpreter = SignatureInterpreter({u'fmt/53':
                        {'extensions': [u'rtf'], 
                         'puid': u'fmt/53', 
                         'display_name': u'Rich Text Format', 
                         'mime_type': u'application/rtf, text/rtf'}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/53', "foo.rtf")
        assert_equal('DOC', format_["display_name"])


class FakeDroidWrapper(object):
    def __init__(self, results):
        self.results = results
    def run_droid_on_folder(self, folder):
        return self.results

class FakeSignatureInterpreter(object):
    def __init__(self, format_):
        self.format_ = format_
    def determine_format(self, puid, filepath):
        return self.format_ 

class TestDroidFileSniffer(object):
    def test_sniff_format(self):
        fake_droid = FakeDroidWrapper({'myfile': u'fmt/56'})
        droid = DroidFileSniffer(fake_droid, 
                    FakeSignatureInterpreter(Formats.by_extension()['xls']), log)
        format_ = droid.sniff_format('myfile')
        assert_equal('XLS', format_["display_name"])

    def test_sniff_format_returns_none_with_unknown_signature(self):
        fake_droid = FakeDroidWrapper({})
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter("foo"), log)
        format_ = droid.sniff_format('myfile')
        assert_equal(None, format_)

    def test_sniff_format_gives_none_with_format_it_doesnt_sniff_well(self):
        fake_droid = FakeDroidWrapper({'myfile': "foo"})
        format_ = Formats.by_extension()["zip"]
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(format_), log)
        format_ = droid.sniff_format('myfile')
        assert_equal(None, format_)

    def test_caching_folder_results(self):
        fake_droid = FakeDroidWrapper({'/a/path/file1': "foo", 
                                       '/a/path/file2': "bar"})
        format_ = Formats.by_extension()["xls"]
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(format_), log)
        assert_equal(format_, droid.sniff_format('/a/path/file1'))
        assert_equal('bar', droid.results_cache['/a/path/file2'])



