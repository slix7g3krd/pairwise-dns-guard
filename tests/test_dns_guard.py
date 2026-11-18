from security.dns_guard import (
    normalize_ip,
    is_private_ip,
    all_answers_public,
    pin_connection,
    redirect_target_ok,
    cache_key
)


def test_private_loopback():
    assert is_private_ip('127.0.0.1') is True

def test_private_10():
    assert is_private_ip('10.0.0.1') is True

def test_public():
    assert is_private_ip('8.8.8.8') is False

def test_normalize():
    assert normalize_ip('127.0.0.1') == '127.0.0.1'

def test_octal():
    assert normalize_ip('0177.0.0.1') is None

def test_ipv6_loop():
    assert is_private_ip('::1') is True

def test_mapped():
    assert normalize_ip('::ffff:127.0.0.1') == '127.0.0.1'

def test_answers_bad():
    assert all_answers_public(['8.8.8.8', '10.0.0.1']) is False

def test_answers_ok():
    assert all_answers_public(['8.8.8.8', '1.1.1.1']) is True

def test_pin_ok():
    assert pin_connection('1.2.3.4', '1.2.3.4') is True

def test_pin_bad():
    assert pin_connection('1.2.3.4', '5.6.7.8') is False

def test_redirect_bad():
    assert redirect_target_ok('http://127.0.0.1') is False

def test_redirect_ok():
    assert redirect_target_ok('https://example.com') is True

def test_redirect_empty():
    assert redirect_target_ok('') is False

def test_cache():
    assert cache_key('a.example', '1.2.3.4') != cache_key('a.example', '5.6.7.8')
