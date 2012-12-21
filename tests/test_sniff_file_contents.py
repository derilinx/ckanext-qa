import os
import logging

from nose.tools import raises, assert_equal

from ckanext.qa.old_sniff_format import old_sniff_file_format, is_json

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('sniff_contents')

def test_is_json():
    assert is_json('5', log)
    assert is_json('-5', log)
    assert is_json('-5.4', log)
    assert is_json('-5.4e5', log)
    assert is_json('-5.4e-5', log)
    assert not is_json('4.', log)
    assert is_json('"hello"', log)
    assert not is_json('hello"', log)
    assert is_json('["hello"]', log)
    assert not is_json('"hello"]', log)
    assert is_json('[5]', log)
    assert is_json('[5, 6]', log)
    assert is_json('[5,6]', log)
    assert is_json('["cat", 6]', log)
    assert is_json('{"cat": 6}', log)
    assert is_json('{"cat":6}', log)
    assert is_json('{"cat": "bob"}', log)
    assert is_json('{"cat": [1, 2]}', log)
    assert is_json('{"cat": [1, 2], "dog": 5, "rabbit": "great"}', log)
    assert not is_json('{"cat": [1, 2}]', log)
    assert is_json('[{"cat": [1]}, 2]', log)

    # false positives of the algorithm:
    #assert not is_json('[{"cat": [1]}2, 2]', log)

