import os
import logging

from nose.tools import raises, assert_equal

from ckanext.dgu.lib.formats import Formats

from ckanext.qa import sniff_format
from ckanext.qa.sniff_format import sniff_file_format, magic_sniff_format, refine_zipped_format
from ckanext.qa.sniff_format import ZipSniffer, highest_scoring_format, overall_format
from ckanext.qa.droid import DroidError

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('sniff')

# for convenience and readability, pre-look up some common formats
XLS = Formats.by_extension()['xls']
DOC = Formats.by_extension()['doc']
PPT = Formats.by_extension()['ppt']
CSV = Formats.by_extension()['csv']
XML = Formats.by_extension()['xml']
ZIP = Formats.by_extension()['zip']
XLS_ZIP = Formats.by_extension()['xls.zip']
XML_ZIP = Formats.by_extension()['xml.zip']
CSV_ZIP = Formats.by_extension()['csv.zip']

class TestSniffFormat:
    @classmethod
    def setup_class(cls):
        # assemble a list of the test fixture data files
        cls.fixture_files = [] # (format_extension, filepath)
        fixture_data_dir = os.path.join(os.path.dirname(__file__), 'data')
        for filename in os.listdir(fixture_data_dir):
            format_extension = '.'.join(filename.split('.')[1:])
            filepath = os.path.join(fixture_data_dir, filename)
            cls.fixture_files.append((format_extension, filepath))

    def test_all(self):
        for format_, filepath in self.fixture_files:
            sniffed_format = sniff_file_format(filepath, log)
            print 'Testing %s %s' % (format_, filepath)
            assert sniffed_format, format_
            assert_equal(sniffed_format['extension'] or \
                         sniffed_format['display_name'].lower(), format_)

    @classmethod
    def check_format(cls, format, filename=None):
        for format_, filepath in cls.fixture_files:
            if format_ == format:
                if filename:
                    if filename in filepath:
                        break
                    else:
                        continue
                else:
                    break
        else:
            assert 0, format #Could not find fixture for format
        sniffed_format = sniff_file_format(filepath, log)
        assert sniffed_format, format_
        assert_equal(sniffed_format['extension'] or \
                     sniffed_format['display_name'].lower(), format_)

    def test_xls(self):
        self.check_format('xls', '10-p108-data-results')
    def test_xls1(self):
        self.check_format('xls', 'August-2010.xls')
    def test_xls2(self):
        self.check_format('xls', 'ukti-admin-spend-nov-2011.xls')
    def test_xls3(self):
        self.check_format('xls', 'decc_local_authority_data_xlsx.xls')
    def test_xls_zip(self):
        self.check_format('xls.zip')
    def test_rdf(self):
        self.check_format('rdf')
    def test_pdf(self):
        self.check_format('pdf')
    def test_kml(self):
        self.check_format('kml')
    def test_rdfa(self):
        self.check_format('rdfa')
    def test_doc(self):
        self.check_format('doc')
    def test_json(self):
        self.check_format('json')
    def test_ods(self):
        self.check_format('ods')
    def test_odt(self):
        self.check_format('odt')
    def test_odp(self):
        self.check_format('odp')
    def test_ppt(self):
        self.check_format('ppt')
    def test_csv(self):
        self.check_format('csv', 'elec00.csv')
    def test_csv1(self):
        self.check_format('csv', 'spendover25kdownloadSep.csv')
    def test_csv2(self):
        self.check_format('csv', '311011.csv')
    def test_csv3(self):
        self.check_format('csv', 'FCOServices_TransparencySpend_May2011.csv')
    def test_csv4(self):
        self.check_format('csv', 'iwfg09_Phos_river_200911.csv')
    def test_csv5(self):
        self.check_format('csv', '9_sus_fisheries_201003.csv')
    def test_csv6(self):
        self.check_format('csv', 'Inpatients_MHA_Machine_readable_dataset_1011.csv')
    def test_shp(self):
        self.check_format('shp')
    def test_html(self):
        self.check_format('html', 'index.html')
    def test_html1(self):
        self.check_format('html', '6a7baac6-d363-4a9d-8e9d-e584f38c05c3.html')
    def test_html2(self):
        self.check_format('html', 'hourly_means.html')
    def test_xml(self):
        self.check_format('xml', 'jobs.xml')
    def test_xml1(self):
        self.check_format('xml', '082010CreditorInvoicesover500.xml')
    def test_xml2(self):
        self.check_format('xml', 'DfidProjects-trunc.xml')
    def test_iati(self):
        self.check_format('iati')
    def test_rss(self):
        self.check_format('rss')
    def test_txt(self):
        self.check_format('txt')
    def test_csv_zip(self):
        self.check_format('csv.zip', 'written_complains.csv.zip')
    def test_csv_zip1(self):
        self.check_format('csv.zip', 'cycle-area-list.csv.zip')
    def test_psv_zip(self):
        self.check_format('psv.zip')
    def test_txt_zip(self):
        self.check_format('txt.zip')
    def test_xml_zip(self):
        self.check_format('xml.zip')
    def test_torrent(self):
        self.check_format('torrent')
    def test_psv(self):
        self.check_format('psv')
    def test_wms(self):
        self.check_format('wms')
    def test_ics(self):
        self.check_format('ics')
    def test_xlsx(self):
        self.check_format('xls', 'defra-qds-1204.xls')
    def test_rtf(self):
        self.check_format('doc', 'foi-bis-quarterly-publications-may-july-2010-special-advisers.doc')


class TestMimeTypeSniffing(object):

    def test_detect_csv_with_magic(self):
        format_ = magic_sniff_format(os.path.join(os.path.dirname(__file__), 'data', '311011.csv'), log)
        assert_equal("text/plain", format_)

class BrokenDroid(object):
    def sniff_format(*args, **kwargs):
        raise DroidError("I'm not working")

class TestErrorHandling(object):

    def setUp(self):
        sniff_format.droid = BrokenDroid()
    def tearDown(self):
        sniff_format.droid = None

    def test_sniff_csv_with_broken_droid(self):
        f = os.path.join(os.path.dirname(__file__), 'data', '311011.csv')
        assert_equal('csv', sniff_file_format(f, log)['extension'])
       
    def test_sniff_xml_with_broken_droid(self):
        f = os.path.join(os.path.dirname(__file__), 'data', 'DfidProjects-trunc.xml')
        assert_equal('xml', sniff_file_format(f, log)['extension'])

class FakeDroid(object):
    def __init__(self, formats, zip_contents):
        self.formats = formats
        self.zip_contents = zip_contents
    def sniff_format(self, filepath):
        return self.formats[filepath]
    def sniff_format_of_zip_contents(self, filepath):
        return self.zip_contents

class TestSniffingZips(object):
    def tearDown(self):
        sniff_format.droid = None
    def test_refine_zipped_format_using_both_droid_and_magic(self):
        f = os.path.join(os.path.dirname(__file__), 'data', 'written_complains.csv.zip')
        sniff_format.droid = FakeDroid({"%s" % f: ZIP},
               {"NHS Written Complaints 2010_11 KO41b meta data.xls": XLS, 
                "NHS Written Complaints 2010_11 KO41a meta data.xls": XLS,
                "Written Complaints 2010_11 KO41a_HCHS.csv": None,
                "Written Complaints 2010_11 KO41b_GP.csv": None})
        format_ = refine_zipped_format(f, log)
        assert_equal('csv.zip', format_['extension'])
        format_ = sniff_file_format(f, log)
        assert_equal('csv.zip', format_['extension'])

    def test_refine_zipped_format_using_only_droid(self):
        f = os.path.join(os.path.dirname(__file__), 'data', 'telephone-network-data.xls.zip')
        sniff_format.droid = FakeDroid({"%s" % f: ZIP},
                                       {"foo": XLS, 
                                        "bar": DOC})
        format_ = refine_zipped_format(f, log)
        assert_equal('xls.zip', format_['extension'])


class TestZipSniffer(object):
    def test_assign_format_of_zip_with_uknown_contents(self):
        formats = {"1": None, "2": None}
        assert_equal(None, highest_scoring_format(formats, log))
        assert_equal(None, overall_format(formats, log))

    def test_assign_format_of_zip_with_partially_known_contents_is_not_known(self):
        formats = {"1": None, "2": XLS}
        assert_equal(None, highest_scoring_format(formats, log))

    def test_assign_format_of_zip_with_fully_known_contents(self):
        formats = {"1": DOC, "2": XLS}
        assert_equal(XLS, highest_scoring_format(formats, log))
        assert_equal(XLS_ZIP, overall_format(formats, log))

    def test_assign_format_of_zip_where_no_contents_score_better_than_zip(self):
        formats = {"1": DOC, "2": PPT}
        assert_equal(ZIP, overall_format(formats, log))

    def test_assign_format_of_zip_where_two_have_same_high_score(self):
        formats = {"1": XML, "2": CSV, "3": CSV}
        assert_equal(CSV_ZIP, overall_format(formats, log))


