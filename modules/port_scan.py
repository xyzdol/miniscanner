# modules/port_scan.py (scaffold)
import socket

def scan(target: str) -> dict:
    # very small TCP connect check for ports 80 and 443
    host = target
    if host.startswith('http://') or host.startswith('https://'):
        import re
        m = re.match(r'https?://([^:/]+)', host)
        if m:
            host = m.group(1)
    ports = [80, 443]
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((host, p))
            open_ports.append(p)
            s.close()
        except Exception:
            pass
    return {
        'name': 'port_scan',
        'target': target,
        'open_ports': open_ports,
        'notes': 'Stub: simple connect scan.'
    }
