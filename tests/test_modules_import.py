import modules.sql_injection as sql
import modules.xss_scan as xss
import modules.port_scan as port

def test_sql_scan_stub():
    # call with invalid local hostname; should return a dict (we don't assert detected)
    res = sql.scan("http://example.com")
    assert isinstance(res, dict)
    assert 'name' in res

def test_xss_scan_stub():
    res = xss.scan("http://example.com")
    assert isinstance(res, dict)
    assert 'name' in res

def test_port_scan_stub():
    res = port.scan("http://example.com")
    assert isinstance(res, dict)
    assert 'name' in res
