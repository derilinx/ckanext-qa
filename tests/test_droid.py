import logging
import os
from nose.tools import raises, assert_equal

from ckanext.dgu.lib.formats import Formats
from ckanext.qa.droid import get_signatures, droid_file_sniffer, SignatureInterpreter, DroidFileSniffer, DROID_INSTALL_DIR, DROID_SIGNATURE_FILE, DROID_CONTAINER_SIGNATURE_FILE

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('droid')

def check_for_droid_installation(func):
    from nose.plugins.skip import SkipTest
    def _(*args, **kwargs):
        if not os.path.exists(DROID_SIGNATURE_FILE) \
            or not os.path.exists(DROID_INSTALL_DIR) \
            or not os.path.exists(DROID_CONTAINER_SIGNATURE_FILE):
            raise SkipTest("Test %s is skipped because Droid is not installed" % func.__name__)
        func(*args, **kwargs)
    _.__name__ = func.__name__
    return _


class TestDroidIntegration(object):

    @check_for_droid_installation
    def test_format_from_puid(self):
        signatures = get_signatures(DROID_SIGNATURE_FILE)
        signature_interpreter = SignatureInterpreter(signatures, log)
        puid = "fmt/215"
        assert_equal (Formats.by_display_name()['PPT'], signature_interpreter.format_from_puid(puid))

    @check_for_droid_installation
    def test_ambiguous_puids(self):
        """This test is to check the signature file is compatible with the 
            Formats.py module. It shouldn't fail unless we update the signature file,
            and only then if there arise ambiguous signatures which match to more than one
            Format. """
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
        droid = droid_file_sniffer(log, DROID_INSTALL_DIR, DROID_SIGNATURE_FILE, DROID_CONTAINER_SIGNATURE_FILE)
        fixture_data_dir = os.path.join(os.path.dirname(__file__), 'data')
        
        signature = droid.puid_of_file(os.path.join(fixture_data_dir, "August-2010.xls"))
        assert_equal("fmt/56", signature)

class TestSignatureInterpreter(object):

    def test_format_from_puid_with_multiple_extensions(self):
        droid = SignatureInterpreter({u'fmt/56' : {'extensions': [u'xlc', u'xlm', u'xls'], 'puid': u'fmt/56', 'display_name': u'Microsoft Excel 3.0 Worksheet (xls)', 'extension': u'xlc', 'mime_type': u'application/vnd.ms-excel'}}, log)
        assert_equal(Formats.by_display_name()['XLS'], droid.format_from_puid(u'fmt/56'))

    def test_signature_interpreter_returns_none_with_missing_signature(self):
        signature_interpreter = SignatureInterpreter({}, log)
        assert_equal(None, signature_interpreter.format_from_puid("foo"))

    def test_signature_interpreter_returns_text_for_json_(self):
        Formats.by_display_name()['TXT']

class FakeDroidWrapper(object):
    def __init__(self, results):
        self.results = results
    def run_droid_on_folder(self, folder):
        return self.results

class FakeSignatureInterpreter(object):
    def __init__(self, format_):
        self.format_ = format_
    def format_from_puid(self, puid):
        return self.format_ 

class TestDroidFileSniffer(object):
    def test_sniff_format(self):
        fake_droid = FakeDroidWrapper({'myfile' : u'fmt/56'})
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(Formats.by_extension()['xls']))
        format_ = droid.sniff_format('myfile')
        assert_equal('XLS', format_["display_name"])

    def test_sniff_format_returns_none_with_unknown_signature(self):
        fake_droid = FakeDroidWrapper({})
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter("foo"))
        format_ = droid.sniff_format('myfile')
        assert_equal(None, format_)

    def test_sniff_format_returns_none_with_format_droid_doesnt_sniff_properly(self):
        fake_droid = FakeDroidWrapper({'myfile' : "foo"})
        format_ = Formats.by_extension()["zip"]
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(format_))
        format_ = droid.sniff_format('myfile')
        assert_equal(None, format_)

    def test_caching_folder_results(self):
        fake_droid = FakeDroidWrapper({'/a/path/file1' : "foo", '/a/path/file2' : "bar"})
        format_ = Formats.by_extension()["xls"]
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(format_))
        assert_equal(format_, droid.sniff_format('/a/path/file1'))
        assert_equal('bar', droid.results_cache['/a/path/file2'])

