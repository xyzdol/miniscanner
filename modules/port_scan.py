# modules/port_scan.py
"""
基础端口扫描模块（安全、轻量，默认小端口集）。
- 避免引入新依赖，仅使用 socket；
- 支持超时参数（秒），默认 0.5；
- 返回与其他模块一致的结构，便于统一报告；
- 仅用于教学演示，请在授权环境中使用。
"""
import socket
from typing import Any, Dict, List, Optional

DEFAULT_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 27017, 3306, 3389, 5432, 5900, 6379, 8080, 8443]


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan(target: str,
         ports: Optional[List[int]] = None,
         timeout: float = 0.5,
         **kwargs: Any) -> Dict[str, Any]:
    """对目标主机进行基础端口扫描。

    参数：
      - target: 目标主机（域名或IP）
      - ports: 要扫描的端口列表，默认使用 DEFAULT_PORTS
      - timeout: 每个端口的连接超时（秒）
    返回：
      统一结构的字典，detected 表示是否发现开放端口；
    """
    ports = ports or DEFAULT_PORTS
    open_ports: List[int] = []

    for p in ports:
        if _is_open(target, int(p), float(timeout)):
            open_ports.append(int(p))

    return {
        "name": "port_scan",
        "target": target,
        "detected": len(open_ports) > 0,
        "vulnerable_payload": {"open_ports": open_ports} if open_ports else None,
        "evidence": [{"port": p, "status": "open"} for p in open_ports],
        "attempts_tried": len(ports),
        "notes": "Basic TCP connect() scan on a small, common port set.",
    }
