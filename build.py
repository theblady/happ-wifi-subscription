import argparse
import base64
import binascii
import concurrent.futures
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener


RAW = 'https://raw.githubusercontent.com/'
SOURCES = {
    'igareck': RAW + 'igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt',
    'wlunlocker': RAW + 'wlunlocker/vpn-configs/main/blacklist_all.txt',
    'morpheusadam': RAW + 'morpheusadam/v2ray-config/main/subs/bundles/best.txt',
    'barry-far': RAW + 'barry-far/V2ray-Config/main/Sub1.txt',
}
PUBLISHED_FEED = 'https://theblady.github.io/happ-wifi-subscription/happ.txt'
SCHEMES = {'vless', 'vmess', 'trojan', 'ss', 'hy2', 'hysteria2'}
TEST_URL = 'https://www.gstatic.com/generate_204'
TRACE_URL = 'https://www.cloudflare.com/cdn-cgi/trace'
MAX_FEED = 5 * 1024 * 1024
TIMEOUT_MS = 10_000
GEO_TIMEOUT = 12
GEO_WORKERS = 8
MAX_GEO_CHECKS = 160
SUBSCRIPTION_SIZE = 20


@dataclass(frozen=True)
class Candidate:
    name: str
    uri: str


@dataclass(frozen=True)
class Result:
    node: Candidate
    delay: int
    ip: str
    country: str


def decode64(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8')


def lines_from_feed(body):
    lines = body.strip().splitlines()
    if any('://' in line and not line.lstrip().startswith('#') for line in lines):
        return lines
    try:
        return decode64(''.join(body.split())).splitlines()
    except (ValueError, binascii.Error):
        return []


def is_public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def valid_host(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = host.rstrip('.').lower()
        return (len(host) <= 253 and re.fullmatch(r'[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+', host)
                and not host.endswith(('.local', '.localhost', '.internal', '.lan', '.test', '.invalid'))
                and not re.fullmatch(r'[\d.]+', host))
    return is_public_ip(host)


def vmess_profile(uri):
    payload = uri.removeprefix('vmess://').split('#', 1)[0]
    profile = json.loads(decode64(payload))
    if not isinstance(profile, dict):
        raise ValueError('Expected a VMess object')
    json.dumps(profile, ensure_ascii=False).encode('utf-8')
    return profile


def destination(uri):
    url = urlsplit(uri)
    if url.scheme == 'vmess' and '@' not in url.netloc:
        profile = vmess_profile(uri)
        port = profile['port']
        if type(port) not in (str, int):
            raise ValueError('Invalid VMess port')
        return str(profile['add']), int(port)
    if url.scheme == 'ss' and '@' not in url.netloc:
        url = urlsplit('ss://' + decode64(url.netloc))
    return url.hostname or '', url.port or 0


def uri_key(uri):
    url = urlsplit(uri)
    if url.scheme == 'vmess' and '@' not in url.netloc:
        profile = vmess_profile(uri)
        profile.pop('ps', None)
        return 'vmess://' + json.dumps(profile, sort_keys=True)
    if url.scheme == 'hy2':
        url = url._replace(scheme='hysteria2')
    options = parse_qsl(url.query, keep_blank_values=True)
    query = urlencode(sorted(options, key=lambda pair: pair[0]))
    return url._replace(query=query, fragment='').geturl()


def candidates(feeds):
    unique = {}
    for body in feeds:
        for line in lines_from_feed(body):
            uri = line.strip()
            base = uri.split('#', 1)[0]
            if base.partition('://')[0] not in SCHEMES or any(c.isspace() for c in base):
                continue
            try:
                host, port = destination(base)
                if not 1 <= port <= 65535 or not valid_host(host):
                    continue
                key = uri_key(base)
            except (ValueError, TypeError, KeyError, binascii.Error):
                continue
            name = hashlib.sha256(key.encode()).hexdigest()[:16]
            unique.setdefault(name, Candidate(name, uri))
    return list(unique.values())


def wifi_pool(current, previous_feed, delays):
    combined = {node.name: node for node in candidates([previous_feed]) if node.name in delays}
    combined.update((node.name, node) for node in current if node.name in delays)
    return sorted(combined.values(), key=lambda node: (delays[node.name], node.name))


def wifi_results(nodes, baseline):
    return [
        Result(node, baseline['delays_ms'][node.name], '', baseline['countries'][node.name])
        for node in nodes
    ]


def rename(uri, label):
    base = uri.split('#', 1)[0]
    if base.startswith('vmess://') and '@' not in urlsplit(base).netloc:
        profile = vmess_profile(base)
        profile['ps'] = label
        encoded = base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
        return 'vmess://' + encoded
    return base + '#' + quote(label, safe='')


def request(url, timeout=15, token=None, data=None, method=None, limit=MAX_FEED):
    headers = {'User-Agent': 'Happ-WiFi-Subscription/1.0'}
    if token is not None:
        headers.update({'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    encoded = None if data is None else json.dumps(data).encode()
    req = Request(url, data=encoded, headers=headers, method=method)
    with build_opener(ProxyHandler({})).open(req, timeout=timeout) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError('Response exceeds size limit')
    return body.decode('utf-8-sig')


def parse_trace(body, direct_ip=None):
    fields = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    ip, country = fields.get('ip', ''), fields.get('loc', '')
    if is_public_ip(ip) and ip != direct_ip and re.fullmatch(r'[A-Z]{2}', country) and country != 'XX':
        return ip, country
    return None


def public_dns(nodes):
    by_host = {}
    for node in nodes:
        host, _ = destination(node.uri)
        by_host.setdefault(host, []).append(node)

    def resolve(host):
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except (OSError, UnicodeError):
            return []
        return sorted(addresses) if all(map(is_public_ip, addresses)) else []

    with concurrent.futures.ThreadPoolExecutor(32) as pool:
        resolved = dict(zip(by_host, pool.map(resolve, by_host)))
    eligible = [node for host, items in by_host.items() if resolved[host] for node in items]
    hosts = {host: ips for host, ips in resolved.items() if ips and not is_public_ip(host)}
    return eligible, hosts


def reserved_sockets(count):
    stack = ExitStack()
    sockets = []
    with stack:
        for _ in range(count):
            sock = stack.enter_context(socket.socket())
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
        return stack.pop_all(), sockets


def provider_files(home, nodes):
    providers = {}
    for node in nodes:
        path = f'./{node.name}.txt'
        (home / path).write_text(rename(node.uri, node.name) + '\n', encoding='utf-8')
        providers[node.name] = {'type': 'file', 'path': path}
    return providers


def check_with_mihomo(nodes, hosts, binary, workers, curl, *, interface=None, target_count=None):
    target_count = target_count or SUBSCRIPTION_SIZE
    direct = parse_trace(request(TRACE_URL))
    if direct is None:
        raise RuntimeError('No direct connection to the geo check endpoint')
    with tempfile.TemporaryDirectory(prefix='happ-probes-') as directory:
        home = Path(directory)
        reservations, sockets = reserved_sockets(GEO_WORKERS + 1)
        with reservations:
            control_port, *listeners = [sock.getsockname()[1] for sock in sockets]
        control = f'http://127.0.0.1:{control_port}'
        token = secrets.token_hex(24)
        groups = [f'probe-{index}' for index in range(GEO_WORKERS)]
        providers = provider_files(home, nodes)
        config = {
            'mode': 'rule',
            'log-level': 'silent',
            'external-controller': f'127.0.0.1:{control_port}',
            'secret': token,
            'profile': {'store-selected': False},
            'hosts': hosts,
            'proxy-providers': providers,
            'proxy-groups': [{'name': group, 'type': 'select', 'use': list(providers)} for group in groups],
            'listeners': [
                {'name': group, 'type': 'http', 'listen': '127.0.0.1', 'port': port, 'proxy': group}
                for group, port in zip(groups, listeners)
            ],
            'rules': ['MATCH,REJECT'],
        }
        if interface:
            config['interface-name'] = interface
        config_path = home / 'config.yaml'
        config_path.write_text(json.dumps(config), encoding='utf-8')

        def api(path, timeout=5, data=None, limit=MAX_FEED):
            return request(control + path, timeout=timeout, token=token, data=data,
                           method='PUT' if data is not None else None, limit=limit)

        with subprocess.Popen([binary, '-d', str(home), '-f', str(config_path)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
            try:
                available = []
                unchanged = 0
                for _ in range(60):
                    if process.poll() is not None:
                        raise RuntimeError(f'Mihomo exited with code {process.returncode}')
                    try:
                        response = json.loads(api('/providers/proxies', timeout=4, limit=16 * 1024 * 1024))
                        loaded = response['providers']
                        current = [node for node in nodes if loaded.get(node.name, {}).get('proxies')]
                        unchanged = unchanged + 1 if len(current) == len(available) else 0
                        available = current
                        if len(available) == len(nodes) or (available and unchanged >= 3):
                            break
                    except OSError:
                        pass
                    time.sleep(0.25)
                if not available:
                    raise RuntimeError('Mihomo could not parse any candidate')
                print(f'Mihomo loaded {len(available)} of {len(nodes)} candidates', flush=True)
                query = urlencode({'url': TEST_URL, 'timeout': TIMEOUT_MS, 'expected': 204})

                def delay(node):
                    path = f'/providers/proxies/{node.name}/{node.name}/healthcheck?{query}'
                    try:
                        ms = json.loads(api(path, timeout=TIMEOUT_MS / 1000 + 2))['delay']
                        return (ms, node) if isinstance(ms, int) and ms > 0 else None
                    except (OSError, ValueError, KeyError):
                        return None

                with concurrent.futures.ThreadPoolExecutor(workers) as pool:
                    passed = sorted(filter(None, pool.map(delay, available)), key=lambda pair: pair[0])
                print(f'{len(passed)} returned an HTTPS response through the proxy', flush=True)

                def locate(item):
                    slot, (ms, node) = item
                    try:
                        api(f'/proxies/{groups[slot]}', data={'name': node.name})
                        response = subprocess.run([
                            curl, '--silent', '--fail', '--max-time', str(GEO_TIMEOUT), '--max-filesize', '4096',
                            '--noproxy', '', '--proxy', f'http://127.0.0.1:{listeners[slot]}', TRACE_URL,
                        ], capture_output=True, text=True, encoding='utf-8', errors='replace',
                            timeout=GEO_TIMEOUT + 2)
                        trace = parse_trace(response.stdout, direct[0]) if response.returncode == 0 else None
                        return Result(node, ms, *trace) if trace else None
                    except (OSError, subprocess.TimeoutExpired):
                        return None

                results = []
                with concurrent.futures.ThreadPoolExecutor(GEO_WORKERS) as pool:
                    for start in range(0, min(len(passed), MAX_GEO_CHECKS), GEO_WORKERS):
                        batch = passed[start:start + GEO_WORKERS]
                        results.extend(filter(None, pool.map(locate, enumerate(batch))))
                        if len(results) >= target_count:
                            break
                return results, len(available), len(passed)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)


def choose(results, limit):
    return sorted(results, key=lambda row: (row.delay, row.node.name))[:limit]


def publish(output, selected, summary):
    if not selected:
        raise ValueError('No verified proxies. Keeping the previous subscription.')
    output.mkdir(parents=True, exist_ok=True)
    ordered = sorted(selected, key=lambda row: (row.country, row.delay))
    feed = ['#profile-title: Wi-Fi Happ']
    feed.extend(rename(row.node.uri, f'{row.country} · {row.node.name[:6]}') for row in ordered)
    summary = dict(
        summary, updated_at=datetime.now(timezone.utc).isoformat(),
        nodes=len(ordered), countries=dict(sorted(Counter(row.country for row in ordered).items()))
    )
    for filename, content in [('happ.txt', '\n'.join(feed) + '\n'),
                              ('status.json', json.dumps(summary, indent=2) + '\n')]:
        target = output / filename
        temporary = target.with_suffix('.tmp')
        temporary.write_bytes(content.encode('utf-8'))
        temporary.replace(target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', default='mihomo')
    parser.add_argument('--curl', default='curl')
    parser.add_argument('--output', type=Path, default=Path('site'))
    parser.add_argument('--workers', type=int, default=48)
    parser.add_argument('--wifi-baseline', type=Path)
    parser.add_argument('--interface')
    parser.add_argument('--record-wifi-baseline', type=Path)
    args = parser.parse_args()
    if args.record_wifi_baseline and (not args.interface or args.wifi_baseline):
        parser.error('Recording a baseline requires --interface and a fresh scan')

    def load_source(item):
        name, url = item
        for attempt in range(3):
            try:
                body = request(url)
                found = len(candidates([body]))
                if found:
                    return name, body, found
            except (OSError, ValueError):
                if attempt < 2:
                    time.sleep(attempt + 1)
        return name, '', 0

    with concurrent.futures.ThreadPoolExecutor(len(SOURCES)) as pool:
        feeds = list(pool.map(load_source, SOURCES.items()))
    counts = {name: count for name, _, count in feeds}
    print('Source counts:', counts, flush=True)
    nodes = candidates(body for _, body, _ in feeds)
    baseline = None
    if args.wifi_baseline:
        baseline = json.loads(args.wifi_baseline.read_text(encoding='utf-8'))
        previous = ''
        if not all(counts.values()):
            try:
                previous = request(PUBLISHED_FEED)
            except (OSError, ValueError):
                pass
        nodes = wifi_pool(nodes, previous, baseline['delays_ms'])
        print(f'{len(nodes)} candidates have a Wi-Fi measurement', flush=True)
    nodes, hosts = public_dns(nodes)
    if not nodes:
        raise SystemExit('No usable source records')
    results, checked, passed = check_with_mihomo(
        nodes, hosts, args.mihomo, args.workers, args.curl,
        interface=args.interface,
        target_count=70 if args.record_wifi_baseline else SUBSCRIPTION_SIZE,
    )
    selected = choose(wifi_results(nodes, baseline) if baseline else results, SUBSCRIPTION_SIZE)
    print(f'{len(results)} with egress in this run; publishing {len(selected)}', flush=True)
    summary = {'sources': counts, 'checked': checked, 'https_ok': passed}
    if baseline:
        summary['wifi_measured_at'] = baseline['measured_at']
    publish(args.output, selected, summary)
    if args.record_wifi_baseline:
        measurements = {
            'measured_at': datetime.now(timezone.utc).isoformat(),
            'delays_ms': {row.node.name: row.delay for row in results},
            'countries': {row.node.name: row.country for row in results},
        }
        args.record_wifi_baseline.write_text(json.dumps(measurements, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
