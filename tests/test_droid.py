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

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

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
        format_ = signature_interpreter.determine_format(puid)
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
    def test_find_puids_of_file(self):
        droid = droid_file_sniffer(log)
        
        signature, contents = droid.puids_of_file(os.path.join(DATA_DIR, "August-2010.xls"))
        assert_equal("fmt/56", signature)
        assert_equal({}, contents)

    @check_for_droid_installation
    def test_softlinks(self):
        droid = droid_file_sniffer(log)
        afile = os.path.join(DATA_DIR, "August-2010.xls")
        alink = os.path.join(DATA_DIR, 'foo')
        try:
            os.system("ln -s %s %s" % (afile, alink))

            signature, _ = droid.puids_of_file(alink)
            assert_equal("fmt/56", signature)
        finally:
            os.remove(alink)

    @check_for_droid_installation
    def test_zip_files(self):
        droid = droid_file_sniffer(log)
        zip_xls_file = os.path.join(DATA_DIR, 'telephone-network-data.xls.zip')

        file_puid, all_puids = droid.puids_of_file(zip_xls_file)
        assert_equal("x-fmt/263", file_puid) 
        assert_equal(11, len(all_puids.keys())) # 11 files in this zip
        assert 'x-fmt/263' not in all_puids.values(), "shouldn't find puid of original zip file in list of contents"
        assert_equal('fmt/61', all_puids.get("hmrc-telephone-network-data-april2009-june2010-prs-v00.xls"))    
        assert_equal('fmt/214', all_puids.get('nhs-direct-telephone-network-data-april-june2009-v00.xlsx'))      
        
    @check_for_droid_installation
    def test_assign_format_of_zip(self):
        puids = {"1": 'fmt/61', "2": 'fmt/214', "3": 'fmt/291', "4": 'fmt/294'}
        puid_of_zip_file = 'x-fmt/263'
        signature_interpreter = SignatureInterpreter(get_signatures(DROID_SIGNATURE_FILE), log)
        formats = signature_interpreter.determine_formats(puids)
        assert_equal(sorted(['XLS', 'XLS', 'ODT', 'ODS']), sorted([format_['display_name'] for format_ in formats.values() if format_]))
        assert_equal('ODS', signature_interpreter.highest_scoring_format(puids)['display_name'])

    @check_for_droid_installation
    def test_sniff_format_of_zip(self):
        zip_xls_file = os.path.join(DATA_DIR, 'telephone-network-data.xls.zip')
        droid = droid_file_sniffer(log)
        format_ = droid.sniff_format(zip_xls_file)
        assert_equal('XLS / Zip', format_['display_name'])

    @check_for_droid_installation
    def test_sniff_format_of_zip_contents(self):
        zip_xls_file = os.path.join(DATA_DIR, 'telephone-network-data.xls.zip')
        droid = droid_file_sniffer(log)
        formats = droid.sniff_format_of_zip_contents(zip_xls_file)
        assert_equal(Formats.by_extension()['xls'], formats.get("hmrc-telephone-network-data-april2009-june2010-prs-v00.xls"))    
        assert_equal(Formats.by_extension()['xlsx'], formats.get('nhs-direct-telephone-network-data-april-june2009-v00.xlsx'))      
        assert_equal(11, len(formats)) # 11 files in this zip
        

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
        assert_equal(None, signature_interpreter.determine_format("foo"))

    def test_sniff_format_ole2(self):
        signature_interpreter = SignatureInterpreter({u'fmt/111':
                        {'extensions': [],
                         'puid': u'fmt/111',
                         'display_name': u'OLE2 Compound Document Format', 
                         'mime_type': ''}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/111')
        assert_equal('XLS', format_["display_name"])

    def test_sniff_works_is_not_doc(self):
        signature_interpreter = SignatureInterpreter({u'fmt/220':
                        {'extensions': [u'wks'], 
                         'puid': u'fmt/220', 
                         'display_name': 
                        u'Microsoft Works Spreadsheet for Windows', 
                         'mime_type': ''}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/220')
        assert_equal(None, format_)

    def test_sniff_rtf_is_a_doc(self):
        signature_interpreter = SignatureInterpreter({u'fmt/53':
                        {'extensions': [u'rtf'], 
                         'puid': u'fmt/53', 
                         'display_name': u'Rich Text Format', 
                         'mime_type': u'application/rtf, text/rtf'}}, log)
        format_ = signature_interpreter.determine_format(u'fmt/53')
        assert_equal('DOC', format_["display_name"])

    def test_assign_format_of_zip_with_uknown_contents(self):
        puids = {"1": None, "2": None}
        signature_interpreter = SignatureInterpreter({}, log)
        formats = signature_interpreter.determine_formats(puids)
        assert_equal({"1": None, "2": None}, formats)
        assert_equal(None, signature_interpreter.highest_scoring_format(puids))

    def test_assign_format_of_zip_with_partially_known_contents_is_not_known(self):
        puids = {"1": None, "2": 'fmt/214'}
        signature_interpreter = SignatureInterpreter({'fmt/214' : {'extensions': [u'xlsx'], 'puid': u'fmt/214', 'display_name': u'Microsoft Excel for Windows', 'mime_type': ''}}, log)
        formats = signature_interpreter.determine_formats(puids)
        assert_equal(None, formats["1"])
        assert_equal('XLS', formats["2"]['display_name'])
        assert_equal(None, signature_interpreter.highest_scoring_format(puids))

class FakeDroidWrapper(object):
    def __init__(self, results):
        self.results = results
    def run_droid_on_folder(self, folder):
        return self.results

class FakeSignatureInterpreter(object):
    def __init__(self, format_):
        self.format_ = format_
    def determine_format(self, puid):
        return self.format_ 

class TestDroidFileSniffer(object):
    def test_sniff_format(self):
        fake_droid = FakeDroidWrapper({'myfile': u'fmt/56'})
        droid = DroidFileSniffer(fake_droid, 
                    FakeSignatureInterpreter(Formats.by_extension()['xls']), log)
        format_ = droid.sniff_format('myfile')
        assert_equal('XLS', format_["display_name"])

    def test_sniff_format_throws_an_excpetion_when_droid_results_dont_contain_file(self):
        fake_droid = FakeDroidWrapper({})
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter("foo"), log)
        try:
            format_ = droid.sniff_format('myfile')
            assert False, "should have thrown an exception because droid didn't find the file"
        except Exception, expected:
            pass

    def test_sniff_format_for_zip(self):
        fake_droid = FakeDroidWrapper({'myfile': "foo"})
        format_ = Formats.by_extension()["zip"]
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(format_), log)
        format_ = droid.sniff_format('myfile')
        assert_equal('Zip', format_['display_name'])

    def test_caching_folder_results(self):
        fake_droid = FakeDroidWrapper({'/a/path/file1': "foo", 
                                       '/a/path/file2': "bar"})
        format_ = Formats.by_extension()["xls"]
        droid = DroidFileSniffer(fake_droid, FakeSignatureInterpreter(format_), log)
        assert_equal(format_, droid.sniff_format('/a/path/file1'))
        assert_equal('bar', droid.results_cache['/a/path/file2'])



