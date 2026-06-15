"""ForensicLab — 딥 패킷 분석.

forensiclab 라이브러리(pcap·netdissect·flows + 80여 종 프로토콜 파서)를 웹에 연결.
업로드한 pcap 을 L2~L4 로 디섹트하고, 표준 포트로 앱 프로토콜을 식별한 뒤
해당 파서로 심층 디코드하여 통계·플로우·보안 하이라이트를 만든다.
"""
import importlib
from collections import Counter, OrderedDict

from flask import request, render_template
from monitor.views.tools import bp, _save_log

MAX_UPLOAD = 100 * 1024 * 1024

# proto_key, 표시 라벨, 카테고리, 표준 포트들, 모듈, 파서 함수명
_PROTOCOLS = [
    # ── ICS / SCADA 제어평면 ──
    ('modbus',  'Modbus/TCP', 'ICS',  [502],          'modbus',  'parse_modbus'),
    ('dnp3',    'DNP3',       'ICS',  [20000],        'dnp3',    'parse_dnp'),
    ('s7comm',  'S7comm',     'ICS',  [102],          's7comm',  'parse_s'),
    ('iec104',  'IEC 60870-5-104', 'ICS', [2404],     'iec104',  'parse_iec'),
    ('bacnet',  'BACnet/IP',  'IoT',  [47808],        'bacnet',  'parse_bacnet'),
    # ── IoT / 검색 ──
    ('mqtt',    'MQTT',       'IoT',  [1883, 8883],   'mqtt',    'parse_mqtt'),
    ('coap',    'CoAP',       'IoT',  [5683],         'coap',    'parse_coap'),
    ('ssdp',    'SSDP/UPnP',  'IoT',  [1900],         'ssdp',    'parse_ssdp'),
    # ── 이름풀이 / 인프라 ──
    ('dns',     'DNS',        'infra',[53],           'dns',     'parse_message'),
    ('mdns',    'mDNS',       'infra',[5353],         'mdns',    'parse_message'),
    ('llmnr',   'LLMNR',      'infra',[5355],         'llmnr',   'parse_message'),
    ('nbns',    'NetBIOS-NS', 'infra',[137],          'nbns',    'parse_nbns'),
    ('dhcp',    'DHCP',       'infra',[67, 68],       'dhcp',    'parse_dhcp'),
    ('ntp',     'NTP',        'infra',[123],          'ntp',     'parse_ntp'),
    ('snmp',    'SNMP',       'infra',[161, 162],     'snmp',    'parse_snmp'),
    ('syslog',  'Syslog',     'infra',[514],          'syslog',  'parse_syslog'),
    ('tftp',    'TFTP',       'infra',[69],           'tftp',    'parse_tftp'),
    ('stun',    'STUN',       'infra',[3478],         'stun',    'parse_stun'),
    # ── 웹 / 원격 접속 ──
    ('http',    'HTTP',       'web',  [80, 8080, 8000],'http',   'parse_request'),
    ('tls',     'TLS',        'web',  [443, 8443],    'tls',     'parse_client_hello'),
    ('ssh',     'SSH',        'remote',[22],          'ssh',     'parse_banner'),
    ('telnet',  'Telnet',     'remote',[23],          'telnet',  'parse_telnet'),
    ('rdp',     'RDP',        'remote',[3389],        'rdp',     'parse_rdp_connection_request'),
    ('vnc',     'VNC',        'remote',[5900, 5901],  'vnc',     'parse_rfb_version'),
    # ── 메일 ──
    ('smtp',    'SMTP',       'mail', [25, 587, 465], 'smtp',    'parse_mail_path'),
    ('pop3',    'POP3',       'mail', [110, 995],     'pop3',    'parse_apop_banner'),
    ('imap',    'IMAP',       'mail', [143, 993],     'imap',    'parse_login_argument'),
    # ── 파일 / 디렉터리 / 인증 ──
    ('ftp',     'FTP',        'file', [21],           'ftp',     'parse_port_argument'),
    ('smb',     'SMB',        'file', [445, 139],     'smb',     'parse_smb'),
    ('ldap',    'LDAP',       'auth', [389, 3268],    'ldap',    'parse_ldap'),
    ('kerberos','Kerberos',   'auth', [88],           'kerberos','parse_kerberos'),
    ('radius',  'RADIUS',     'auth', [1812, 1813, 1645],'radius','parse_radius'),
    # ── 데이터베이스 ──
    ('mysql',   'MySQL',      'db',   [3306],         'mysql',   'parse_mysql_handshake'),
    ('postgres','PostgreSQL', 'db',   [5432],         'postgres','parse_postgres_startup'),
    ('mssql',   'MSSQL',      'db',   [1433],         'mssql',   'parse_mssql_prelogin'),
    ('redis',   'Redis',      'db',   [6379],         'redis',   'parse_redis_command'),
    ('mongodb', 'MongoDB',    'db',   [27017],        'mongodb', 'parse_mongodb_message'),
    ('memcached','Memcached', 'db',   [11211],        'memcached','parse_memcached_command'),
    ('oracle',  'Oracle TNS', 'db',   [1521],         'oracle',  'parse_oracle_connect'),
    # ── VoIP / 통신 ──
    ('sip',     'SIP',        'voip', [5060, 5061],   'sip',     'parse_request'),
    # ── VPN / 보안 ──
    ('ike',     'IKE/IPsec',  'vpn',  [500, 4500],    'ike',     'parse_ike'),
    ('l2tp',    'L2TP',       'vpn',  [1701],         'l2tp',    'parse_l'),
    ('pptp',    'PPTP',       'vpn',  [1723],         'pptp',    'parse_pptp'),
    ('openvpn', 'OpenVPN',    'vpn',  [1194],         'openvpn', 'parse_openvpn'),
    ('wireguard','WireGuard', 'vpn',  [51820],        'wireguard','parse_wireguard'),
    # ── 기타 ──
    ('whois',   'WHOIS',      'misc', [43],           'whois',   'parse_whois'),
    ('finger',  'Finger',     'misc', [79],           'finger',  'parse_finger'),
    ('irc',     'IRC',        'misc', [6667, 6697],   'irc',     'parse_prefix'),
    ('socks',   'SOCKS',      'misc', [1080],         'socks',   'parse_socks'),
]

# 포트 → 프로토콜 엔트리
_PORT_MAP = {}
for _ent in _PROTOCOLS:
    for _p in _ent[3]:
        _PORT_MAP.setdefault(_p, _ent)

# 평문·무인증으로 자격증명/제어가 노출될 수 있는 프로토콜
_CLEARTEXT = {'http', 'ftp', 'telnet', 'pop3', 'imap', 'smtp', 'snmp',
              'finger', 'irc', 'vnc', 'ldap', 'tftp', 'redis', 'memcached'}
_ICS = {'ICS'}

_parser_cache = {}


def _get_parser(module, func):
    key = (module, func)
    if key not in _parser_cache:
        try:
            mod = importlib.import_module('forensiclab.' + module)
            _parser_cache[key] = getattr(mod, func, None)
        except Exception:
            _parser_cache[key] = None
    return _parser_cache[key]


def _l4_payload(data, ipv4):
    """IPv4 페이로드(TCP/UDP)에서 앱 계층 바이트를 잘라낸다."""
    off = ipv4.payload_offset
    if ipv4.protocol == 6:  # TCP
        if len(data) - off < 13:
            return b''
        data_off = (data[off + 12] >> 4) * 4
        return data[off + data_off:]
    if ipv4.protocol == 17:  # UDP
        return data[off + 8:]
    return b''


def _fields(obj, limit=10):
    """파싱 결과 객체에서 표시용 스칼라 필드를 안전하게 추출."""
    import dataclasses
    try:
        d = dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else dict(vars(obj))
    except Exception:
        return {'value': str(obj)[:120]}
    out = OrderedDict()
    for k, v in d.items():
        if k.startswith('_') or v is None:
            continue
        if isinstance(v, (bytes, bytearray)):
            v = v[:24].hex()
        elif isinstance(v, (list, tuple, dict)):
            v = str(v)[:100]
        elif not isinstance(v, (str, int, float, bool)):
            v = str(v)[:100]
        out[k] = v
        if len(out) >= limit:
            break
    # 자주 쓰는 헬퍼 프로퍼티가 있으면 덧붙임
    for prop in ('function_name', 'application_function_name', 'service_name',
                 'type_name', 'is_write', 'is_control', 'is_request'):
        try:
            val = getattr(obj, prop, None)
            if val is not None and not callable(val):
                out[prop] = val if isinstance(val, (str, int, float, bool)) else str(val)[:60]
        except Exception:
            pass
    return out


def _deep_analyze(raw):
    import forensiclab.pcap as fpcap
    import forensiclab.netdissect as nd
    import forensiclab.flows as fflows

    header, packets = fpcap.parse(raw)
    linktype = header.linktype

    l4_dist = Counter()
    app_dist = Counter()
    app_cat = {}
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports = Counter()
    samples = OrderedDict()
    diss_for_flows = []
    truncated = 0
    first_ts = last_ts = None

    for pkt in packets:
        data = pkt.data
        if pkt.truncated:
            truncated += 1
        ts = None
        try:
            ts = pkt.timestamp.timestamp() if pkt.timestamp else None
        except Exception:
            ts = None
        if ts is not None:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)

        d = nd.dissect(data, linktype)
        diss_for_flows.append((d, pkt.original_len or len(data), ts))

        if d.ipv4 is None:
            l4_dist['non-IP'] += 1
            continue
        l4_dist[d.protocol_name] += 1
        src_ips[d.ipv4.src_ip] += 1
        dst_ips[d.ipv4.dst_ip] += 1
        if d.dst_port is not None:
            dst_ports[d.dst_port] += 1

        # 포트로 앱 프로토콜 식별 (목적지 우선, 없으면 출발지)
        ent = None
        for port in (d.dst_port, d.src_port):
            if port in _PORT_MAP:
                ent = _PORT_MAP[port]
                break
        if ent is None:
            continue
        key, label, cat = ent[0], ent[1], ent[2]
        app_dist[label] += 1
        app_cat[label] = cat

        # 심층 디코드 (best-effort)
        if len(samples.get(label, [])) >= 6:
            continue
        parser = _get_parser(ent[4], ent[5])
        if parser is None:
            continue
        payload = _l4_payload(data, d.ipv4)
        if not payload:
            continue
        try:
            parsed = parser(payload)
        except Exception:
            parsed = None
        if parsed is None:
            continue
        rec = _fields(parsed)
        rec['_src'] = f"{d.ipv4.src_ip}:{d.src_port}"
        rec['_dst'] = f"{d.ipv4.dst_ip}:{d.dst_port}"
        samples.setdefault(label, []).append(rec)

    # 플로우 집계
    flows = []
    try:
        fl = fflows.aggregate_flows(diss_for_flows)
        fl.sort(key=lambda f: f.packets, reverse=True)
        for f in fl[:20]:
            k = f.key
            flows.append({
                'proto': k.protocol_name,
                'a': f"{k.ip_a}:{k.port_a}" if k.port_a else k.ip_a,
                'b': f"{k.ip_b}:{k.port_b}" if k.port_b else k.ip_b,
                'packets': f.packets,
                'bytes': f.bytes_total,
                'dur': round(f.duration, 2) if f.duration is not None else None,
            })
    except Exception:
        pass

    # 보안 하이라이트
    highlights = []
    for label, cnt in app_dist.most_common():
        cat = app_cat.get(label)
        key = next((e[0] for e in _PROTOCOLS if e[1] == label), label)
        if cat == 'ICS':
            highlights.append({
                'level': 'danger',
                'text': f"ICS/SCADA 제어평면 트래픽: {label} {cnt:,}패킷 — "
                        f"무인증·평문 산업제어 프로토콜로, 포트 노출 자체가 중요 인프라 정황입니다."
            })
        elif cat == 'IoT' and key in ('bacnet', 'coap', 'mqtt'):
            highlights.append({
                'level': 'warn',
                'text': f"IoT/빌딩 제어 트래픽: {label} {cnt:,}패킷 — 장치 열거·설정 조작에 주의."
            })
        elif key in _CLEARTEXT:
            highlights.append({
                'level': 'warn',
                'text': f"평문/무인증 프로토콜: {label} {cnt:,}패킷 — 자격증명·데이터가 평문 노출될 수 있습니다."
            })
    if truncated:
        highlights.append({
            'level': 'info',
            'text': f"snaplen 으로 잘린 패킷 {truncated:,}개 — 페이로드가 일부만 캡처되어 심층 디코드가 제한될 수 있습니다."
        })

    def _top(counter, n=10):
        return counter.most_common(n)

    timespan = None
    if first_ts and last_ts:
        from datetime import datetime, timezone
        a = datetime.fromtimestamp(first_ts, timezone.utc)
        b = datetime.fromtimestamp(last_ts, timezone.utc)
        timespan = {
            'start': a.strftime('%Y-%m-%d %H:%M:%S'),
            'end': b.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': round(last_ts - first_ts, 2),
        }

    return {
        'total': len(packets),
        'linktype': linktype,
        'truncated': truncated,
        'timespan': timespan,
        'l4_dist': _top(l4_dist, 8),
        'app_dist': [(lbl, cnt, app_cat.get(lbl)) for lbl, cnt in app_dist.most_common()],
        'app_proto_count': len(app_dist),
        'top_src_ips': _top(src_ips),
        'top_dst_ips': _top(dst_ips),
        'top_dst_ports': [{'port': p, 'count': c,
                           'service': (_PORT_MAP[p][1] if p in _PORT_MAP else '')}
                          for p, c in _top(dst_ports)],
        'flows': flows,
        'samples': samples,
        'highlights': highlights,
    }


@bp.route('/deep-pcap', methods=['GET', 'POST'])
def deep_pcap_tool():
    result = None
    error = None
    share_token = None
    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/deep_pcap.html', error=error)
            data = f.read(MAX_UPLOAD)
            try:
                result = _deep_analyze(data)
            except Exception as e:
                msg = str(e)
                if 'magic' in msg.lower() or 'pcapng' in msg.lower() or 'header' in msg.lower():
                    error = ('libpcap(.pcap) 형식만 지원합니다. pcapng/cap 일 수 있으니 '
                             'Wireshark에서 "다른 이름으로 저장 → pcap" 으로 변환해 주세요. (' + msg + ')')
                else:
                    error = 'pcap 분석 실패: ' + msg
                return render_template('tools/deep_pcap.html', error=error)
            result['filename'] = f.filename
            result['file_size'] = len(data)
            summary = (f"{f.filename} | {result['total']:,}개 패킷 | "
                       f"앱 프로토콜 {result['app_proto_count']}종 | "
                       f"하이라이트 {len(result['highlights'])}건")
            share_token = _save_log('deep-pcap', '딥 패킷 분석', f.filename, len(data), summary, {
                'filename': f.filename,
                'total': result['total'],
                'app_dist': result['app_dist'],
                'top_dst_ips': result['top_dst_ips'],
                'top_dst_ports': result['top_dst_ports'],
                'highlights': result['highlights'],
                'flows': result['flows'][:10],
            })
        except Exception as e:
            error = str(e)
    return render_template('tools/deep_pcap.html', result=result, error=error,
                           share_token=share_token)
