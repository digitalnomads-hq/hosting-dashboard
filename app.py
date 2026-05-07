import os
import json
import re
import sqlite3
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import dns.resolver
import whois
import yaml
from flask import Flask, render_template, request, redirect, jsonify

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'config.yaml')
# When deployed, DATA_DIR points to the persistent Fly.io volume (/data)
DATA_DIR  = os.environ.get('DATA_DIR', BASE_DIR)
DB_FILE   = os.path.join(DATA_DIR, 'sites.db')
CACHE_TTL = 86400  # 24 hours

_refresh_state  = {'running': False, 'progress': 0, 'total': 0, 'error': None}
_refresh_lock   = threading.Lock()
_backfill_state = {'running': False, 'progress': 0, 'total': 0, 'filled': 0}
_uptime_state   = {'running': False, 'progress': 0, 'total': 0}


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_config():
    """Load config from config.yaml, with env var overrides for deployed environments."""
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            cfg = yaml.safe_load(f) or {}

    # Allow individual keys to be overridden by environment variables
    # (used on Fly.io where secrets are injected as env vars)
    def _env(key, default):
        return os.environ.get(key) or default

    cfg.setdefault('cloudways', {})
    cfg['cloudways']['email']   = _env('CLOUDWAYS_EMAIL',   cfg['cloudways'].get('email', ''))
    cfg['cloudways']['api_key'] = _env('CLOUDWAYS_API_KEY', cfg['cloudways'].get('api_key', ''))

    cfg.setdefault('kinsta', {})
    cfg['kinsta']['api_key']    = _env('KINSTA_API_KEY',    cfg['kinsta'].get('api_key', ''))
    cfg['kinsta']['company_id'] = _env('KINSTA_COMPANY_ID', cfg['kinsta'].get('company_id', ''))

    cfg.setdefault('cloudns', {})
    cfg['cloudns']['auth_id']       = _env('CLOUDNS_AUTH_ID',       cfg['cloudns'].get('auth_id', ''))
    cfg['cloudns']['auth_password'] = _env('CLOUDNS_AUTH_PASSWORD', cfg['cloudns'].get('auth_password', ''))

    cfg.setdefault('whoapi', {})
    cfg['whoapi']['api_key'] = _env('WHOAPI_KEY', cfg['whoapi'].get('api_key', ''))

    cfg.setdefault('teamwork', {})
    cfg['teamwork']['site_url']   = _env('TEAMWORK_SITE_URL',   cfg['teamwork'].get('site_url', ''))
    cfg['teamwork']['api_key']    = _env('TEAMWORK_API_KEY',    cfg['teamwork'].get('api_key', ''))
    cfg['teamwork']['project_id'] = int(_env('TEAMWORK_PROJECT_ID', cfg['teamwork'].get('project_id', 0)) or 0)

    cfg.setdefault('elasticemail', {})
    cfg['elasticemail']['api_key'] = _env('ELASTICEMAIL_API_KEY', cfg['elasticemail'].get('api_key', ''))

    return cfg


def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sites (
                domain        TEXT PRIMARY KEY,
                name          TEXT,
                hosting_provider TEXT,
                server_name   TEXT,
                ip_address    TEXT,
                ip_org        TEXT,
                registrar     TEXT,
                expiry_date   TEXT,
                nameservers   TEXT,
                dns_provider  TEXT,
                notes         TEXT,
                is_manual     INTEGER DEFAULT 0,
                last_updated  INTEGER
            )
        ''')
        cols = [r[1] for r in conn.execute('PRAGMA table_info(sites)').fetchall()]
        if 'ip_org' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN ip_org TEXT DEFAULT ""')
        if 'teamwork_task_id' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN teamwork_task_id TEXT DEFAULT ""')
        if 'teamwork_assignee' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN teamwork_assignee TEXT DEFAULT ""')
        if 'uptime_status' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN uptime_status TEXT DEFAULT "unknown"')
        if 'uptime_checked' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN uptime_checked INTEGER DEFAULT 0')
        conn.commit()


# ---------------------------------------------------------------------------
# DNS / WHOIS helpers
# ---------------------------------------------------------------------------

def make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = 5
    r.lifetime = 5
    return r


def lookup_dns(domain):
    """Returns (ip, nameservers). Tries apex and www fallback."""
    resolver = make_resolver()
    apex = domain.removeprefix('www.')
    ip = None
    nameservers = []

    for candidate in [apex, f'www.{apex}']:
        try:
            ip = str(resolver.resolve(candidate, 'A')[0])
            break
        except Exception:
            pass

    try:
        nameservers = sorted(str(ns).rstrip('.') for ns in resolver.resolve(apex, 'NS'))
    except Exception:
        pass

    return ip, nameservers


def _apex_domain(domain):
    """Best-effort registrable domain — strips subdomains beyond known AU SLDs."""
    parts = domain.rstrip('.').split('.')
    au_slds = {'com', 'net', 'org', 'edu', 'gov', 'asn', 'id', 'act', 'nsw', 'nt', 'qld', 'sa', 'tas', 'vic', 'wa'}
    if len(parts) >= 3 and parts[-1] == 'au' and parts[-2] in au_slds:
        return '.'.join(parts[-3:])   # name.com.au
    if len(parts) >= 2 and parts[-1] == 'au':
        return '.'.join(parts[-2:])   # name.au
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain


def _parse_rdap_response(data):
    """Extract (registrar, expiry_str) from an RDAP JSON response dict."""
    registrar = None
    expiry_str = None
    for entity in data.get('entities', []):
        if 'registrar' in entity.get('roles', []):
            vcard = entity.get('vcardArray', [None, []])[1]
            for field in vcard:
                if field[0] == 'fn':
                    registrar = field[3]
                    break
    for event in data.get('events', []):
        if event.get('eventAction') == 'expiration':
            expiry_str = event['eventDate'][:10]
    return registrar, expiry_str


def _lookup_whoapi(apex):
    """Look up registrar/expiry via WhoAPI. Returns (registrar, expiry_str) or (None, None)."""
    config = load_config()
    api_key = config.get('whoapi', {}).get('api_key', '')
    if not api_key:
        return None, None
    try:
        r = requests.get(
            'https://api.whoapi.com/',
            params={'apikey': api_key, 'r': 'whois', 'domain': apex},
            timeout=10,
        )
        data = r.json()
        if data.get('status') == 0:
            registrar = data.get('registrar') or data.get('whois_name') or None
            expiry_raw = data.get('date_expires') or None
            expiry_str = None
            if expiry_raw:
                try:
                    expiry_str = datetime.strptime(expiry_raw[:10], '%Y-%m-%d').strftime('%Y-%m-%d')
                except Exception:
                    pass
            return registrar, expiry_str
    except Exception:
        pass
    return None, None


def lookup_whois(domain):
    """Returns (registrar, expiry_date_str). Tries WhoAPI → RDAP → python-whois."""
    apex = _apex_domain(domain)
    is_au = apex.endswith('.au')

    # --- WhoAPI (works for .au where RDAP rate-limits and port 43 is often blocked) ---
    registrar, expiry_str = _lookup_whoapi(apex)
    if registrar or expiry_str:
        return registrar, expiry_str

    # --- RDAP ---
    rdap_urls = (
        [f'https://rdap.cctld.au/rdap/domain/{apex}', f'https://rdap.org/domain/{apex}']
        if is_au else
        [f'https://rdap.org/domain/{apex}']
    )
    for url in rdap_urls:
        try:
            r = requests.get(url, timeout=10, headers={'Accept': 'application/rdap+json'})
            if r.status_code == 200:
                registrar, expiry_str = _parse_rdap_response(r.json())
                if registrar or expiry_str:
                    return registrar, expiry_str
            elif r.status_code == 429:
                time.sleep(5)
        except Exception:
            pass

    # --- python-whois (port 43, works on most networks for non-.au) ---
    try:
        w = whois.whois(apex)
        registrar = w.registrar or None
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        expiry_str = expiry.strftime('%Y-%m-%d') if expiry else None
        if registrar or expiry_str:
            return registrar, expiry_str
    except Exception:
        pass

    return None, None


def lookup_ip_org(ip):
    """Return the organisation that owns an IP via ipinfo.io (free tier, 50k/month)."""
    if not ip:
        return ''
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        org = r.json().get('org', '')
        return re.sub(r'^AS\d+\s+', '', org).strip()
    except Exception:
        pass
    return ''


def detect_dns_provider(nameservers):
    ns = ' '.join(nameservers).lower()
    if 'cloudflare' in ns:       return 'Cloudflare'
    if 'awsdns' in ns:           return 'AWS Route53'
    if 'domaincontrol' in ns:    return 'GoDaddy'
    if 'registrar-servers' in ns: return 'Namecheap'
    if 'googledomains' in ns:    return 'Google Domains'
    if 'ns-cloud' in ns:         return 'Google Cloud DNS'
    if 'digitalocean' in ns:     return 'DigitalOcean'
    if 'hover' in ns:            return 'Hover'
    if 'netlify' in ns:          return 'Netlify'
    if 'cloudns' in ns:          return 'ClouDNS'
    if nameservers:
        parts = nameservers[0].rstrip('.').split('.')
        return parts[-2].title() if len(parts) >= 2 else nameservers[0]
    return 'Unknown'


# ---------------------------------------------------------------------------
# Cloudways API
# ---------------------------------------------------------------------------

def _cloudways_token(email, api_key):
    r = requests.post(
        'https://api.cloudways.com/api/v1/oauth/access_token',
        json={'email': email, 'api_key': api_key},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()['access_token']


def fetch_cloudways_sites(cw_cfg):
    sites = []
    try:
        token = _cloudways_token(cw_cfg['email'], cw_cfg['api_key'])
        r = requests.get(
            'https://api.cloudways.com/api/v1/server',
            headers={'Authorization': f'Bearer {token}'},
            timeout=15,
        )
        r.raise_for_status()
        for server in r.json().get('servers', []):
            server_ip    = server.get('public_ip', '')
            server_label = server.get('label', '')
            for app_data in server.get('apps', []):
                raw_domain = (app_data.get('cname') or app_data.get('app_fqdn', '')).strip()
                domain = raw_domain.removeprefix('www.').rstrip('.')
                if domain:
                    sites.append({
                        'domain':           domain,
                        'name':             app_data.get('label', domain),
                        'hosting_provider': 'Cloudways',
                        'server_name':      server_label,
                        'ip_address':       server_ip,
                        'is_manual':        0,
                    })
    except Exception as e:
        print(f'[Cloudways] Error: {e}')
    return sites


# ---------------------------------------------------------------------------
# Kinsta API
# ---------------------------------------------------------------------------

def _kinsta_site_domain(site_id, headers):
    """Fetch the primary live domain for a single Kinsta site."""
    try:
        r = requests.get(f'https://api.kinsta.com/v2/sites/{site_id}', headers=headers, timeout=20)
        r.raise_for_status()
        for env in r.json().get('site', {}).get('environments', []):
            if env.get('name') == 'live' or env.get('display_name', '').lower() == 'live':
                for d in env.get('domains', []):
                    name = d.get('name', '') if isinstance(d, dict) else str(d)
                    clean = name.removeprefix('www.').rstrip('.')
                    if clean and not clean.endswith('.kinsta.cloud') and not clean.startswith('*.'):
                        return clean
    except Exception as e:
        print(f'[Kinsta] Error fetching site {site_id}: {e}')
    return None


def fetch_kinsta_sites(ki_cfg):
    sites = []
    try:
        headers = {'Authorization': f'Bearer {ki_cfg["api_key"]}'}
        params  = {}
        if ki_cfg.get('company_id'):
            params['company'] = ki_cfg['company_id']

        r = requests.get('https://api.kinsta.com/v2/sites', headers=headers, params=params, timeout=20)
        r.raise_for_status()
        site_list = r.json().get('company', {}).get('sites', [])
        print(f'[Kinsta] Found {len(site_list)} sites, fetching domains…')

        # Environments/domains require a per-site call — do it concurrently
        with ThreadPoolExecutor(max_workers=10) as ex:
            future_to_site = {
                ex.submit(_kinsta_site_domain, s['id'], headers): s
                for s in site_list
            }
            for future, site in future_to_site.items():
                domain = future.result()
                if domain:
                    sites.append({
                        'domain':           domain,
                        'name':             site.get('display_name') or site.get('name', domain),
                        'hosting_provider': 'Kinsta',
                        'server_name':      '',
                        'ip_address':       '',
                        'is_manual':        0,
                    })

    except Exception as e:
        print(f'[Kinsta] Error: {e}')
    return sites


# ---------------------------------------------------------------------------
# ClouDNS API
# ---------------------------------------------------------------------------

def fetch_cloudns_zones(cloudns_cfg):
    """Returns a set of domain names whose DNS is managed in ClouDNS."""
    zones = set()
    auth = {
        'auth-id':       cloudns_cfg['auth_id'],
        'auth-password': cloudns_cfg['auth_password'],
    }
    page = 1
    rows = 100
    while True:
        try:
            r = requests.get(
                'https://api.cloudns.net/dns/list-zones.json',
                params={**auth, 'page': page, 'rows-per-page': rows},
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()

            # API returns a list of zone objects (or a dict with 'status' on error)
            if isinstance(data, dict):
                if data.get('status') == 'Failed':
                    print(f'[ClouDNS] API error: {data.get("statusDescription")}')
                break

            for zone in data:
                if isinstance(zone, dict) and zone.get('name'):
                    zones.add(zone['name'].rstrip('.'))

            if len(data) < rows:
                break
            page += 1
        except Exception as e:
            print(f'[ClouDNS] Error fetching zones (page {page}): {e}')
            break

    return zones


def fetch_cloudns_a_record(domain, cloudns_cfg):
    """Returns the first A record IP for the domain from ClouDNS, or None."""
    auth = {
        'auth-id':       cloudns_cfg['auth_id'],
        'auth-password': cloudns_cfg['auth_password'],
    }
    try:
        r = requests.get(
            'https://api.cloudns.net/dns/records.json',
            params={**auth, 'domain-name': domain, 'type': 'A'},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and 'error' not in data:
            for rec in data.values():
                if isinstance(rec, dict) and rec.get('type') == 'A' and rec.get('host') in ('', '@'):
                    return rec.get('record')
    except Exception as e:
        print(f'[ClouDNS] Error fetching A record for {domain}: {e}')
    return None


# ---------------------------------------------------------------------------
# Site enrichment (DNS + WHOIS)
# ---------------------------------------------------------------------------

def enrich_site(site_data, cloudns_zones=None, cloudns_cfg=None):
    domain = site_data['domain']
    apex   = domain.removeprefix('www.')

    in_cloudns = cloudns_zones and apex in cloudns_zones

    # IP: prefer ClouDNS authoritative record if available, fall back to DNS lookup
    if in_cloudns and cloudns_cfg:
        ip = fetch_cloudns_a_record(apex, cloudns_cfg) or None
    else:
        ip = None

    if not ip:
        dns_ip, nameservers = lookup_dns(domain)
        ip = dns_ip or site_data.get('ip_address', '')
    else:
        _, nameservers = lookup_dns(domain)

    dns_provider = 'ClouDNS' if in_cloudns else detect_dns_provider(nameservers)
    registrar, expiry = lookup_whois(apex)
    ip_org = lookup_ip_org(ip) if ip else ''

    return {
        **site_data,
        'ip_address':   ip or '',
        'ip_org':       ip_org,
        'registrar':    registrar or '',
        'expiry_date':  expiry or '',
        'nameservers':  json.dumps(nameservers),
        'dns_provider': dns_provider,
        'last_updated': int(time.time()),
    }


# ---------------------------------------------------------------------------
# Teamwork
# ---------------------------------------------------------------------------

_TW_SKIP = {'dont delete', 'check tpp for domain renewals'}

def _tw_clean_domain(raw):
    url = re.sub(r'^https?://', '', str(raw).strip().lower())
    return url.rstrip('/').removeprefix('www.').split('/')[0]


def fetch_teamwork_tasks(tw_cfg):
    """Return dict of {domain: {'task_id': str, 'assignee': str}} from the Web Hosting project."""
    base = tw_cfg['site_url'].rstrip('/')
    auth = (tw_cfg['api_key'], 'x')
    project_id = tw_cfg['project_id']

    # Get all task lists
    r = requests.get(f'{base}/projects/{project_id}/tasklists.json', auth=auth, timeout=10)
    r.raise_for_status()
    task_lists = r.json().get('tasklists', [])

    domain_map = {}  # domain -> {task_id, assignee}

    for tl in task_lists:
        list_id = tl['id']
        assignee = tl['name']

        r = requests.get(f'{base}/tasklists/{list_id}/tasks.json', auth=auth,
                         params={'includeCompletedTasks': '0'}, timeout=15)
        r.raise_for_status()
        tasks = r.json().get('todo-items', [])

        for t in tasks:
            content = t['content'].strip()
            lower = content.lower()
            if lower in _TW_SKIP or 'hosting management' in lower:
                continue
            domain = _tw_clean_domain(content)
            if not domain or ' ' in domain:
                continue
            task_id = str(t['id'])
            if domain in domain_map:
                # Multiple assignees — comma-separate
                existing = domain_map[domain]
                if task_id not in existing['task_id']:
                    existing['task_id'] += f',{task_id}'
                    existing['assignee'] += f',{assignee}'
            else:
                domain_map[domain] = {'task_id': task_id, 'assignee': assignee}

    return domain_map


def do_sync_teamwork():
    config = load_config()
    tw_cfg = config.get('teamwork', {})
    if not tw_cfg:
        print('[Teamwork sync] No teamwork config found.')
        return

    print('[Teamwork sync] Fetching tasks…')
    try:
        domain_map = fetch_teamwork_tasks(tw_cfg)
    except Exception as e:
        print(f'[Teamwork sync] Failed to fetch tasks: {e}')
        return

    print(f'[Teamwork sync] Found {len(domain_map)} domain tasks')

    with sqlite3.connect(DB_FILE) as conn:
        existing = {r[0] for r in conn.execute('SELECT domain FROM sites').fetchall()}

        # Clear existing teamwork data
        conn.execute('UPDATE sites SET teamwork_task_id = "", teamwork_assignee = ""')
        matched = 0
        new_domains = []

        for domain, info in domain_map.items():
            if domain in existing:
                conn.execute(
                    'UPDATE sites SET teamwork_task_id = ?, teamwork_assignee = ? WHERE domain = ?',
                    (info['task_id'], info['assignee'], domain)
                )
                matched += 1
            else:
                new_domains.append((domain, info))

        conn.commit()

    print(f'[Teamwork sync] Matched {matched}/{len(domain_map)} — enriching {len(new_domains)} new domains…')

    for domain, info in new_domains:
        try:
            ip, nameservers = lookup_dns(domain)
            registrar, expiry = lookup_whois(domain)
            ip_org = lookup_ip_org(ip) if ip else ''
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute('''
                    INSERT OR IGNORE INTO sites
                    (domain, name, hosting_provider, server_name, ip_address, ip_org,
                     registrar, expiry_date, nameservers, dns_provider,
                     notes, is_manual, last_updated, teamwork_task_id, teamwork_assignee)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ''', (
                    domain, domain, 'External', '',
                    ip or '', ip_org,
                    registrar or '', expiry or '',
                    json.dumps(nameservers),
                    detect_dns_provider(nameservers),
                    'Added via Teamwork sync', 1,
                    int(time.time()),
                    info['task_id'], info['assignee'],
                ))
            print(f'[Teamwork sync] Added {domain} ({info["assignee"]})')
            time.sleep(1)
        except Exception as e:
            print(f'[Teamwork sync] Failed to add {domain}: {e}')

    print(f'[Teamwork sync] Done — {matched} matched, {len(new_domains)} added.')


# ---------------------------------------------------------------------------
# Full refresh
# ---------------------------------------------------------------------------

def do_refresh():
    global _refresh_state
    with _refresh_lock:
        if _refresh_state['running']:
            return
        _refresh_state = {'running': True, 'progress': 0, 'total': 0, 'error': None}

    try:
        config = load_config()
        all_sites = {}

        # --- Cloudways ---
        cw = config.get('cloudways', {})
        if cw.get('email') and cw.get('api_key'):
            for s in fetch_cloudways_sites(cw):
                all_sites[s['domain']] = s

        # --- Kinsta ---
        ki = config.get('kinsta', {})
        if ki.get('api_key'):
            for s in fetch_kinsta_sites(ki):
                if s['domain'] not in all_sites:
                    all_sites[s['domain']] = s

        # --- Manual sites ---
        for site in config.get('manual_sites', []):
            domain = site.get('domain', '').strip()
            if domain and domain not in all_sites:
                all_sites[domain] = {
                    'domain':           domain,
                    'name':             site.get('name', domain),
                    'hosting_provider': site.get('host', 'External'),
                    'server_name':      '',
                    'ip_address':       '',
                    'notes':            site.get('notes', ''),
                    'is_manual':        1,
                }

        # --- ClouDNS zones ---
        cloudns_cfg   = config.get('cloudns', {})
        cloudns_zones = set()
        if cloudns_cfg.get('auth_id') and cloudns_cfg.get('auth_password'):
            cloudns_zones = fetch_cloudns_zones(cloudns_cfg)
            print(f'[ClouDNS] Found {len(cloudns_zones)} zones')

        _refresh_state['total'] = len(all_sites)

        # Wipe existing (non-manual) entries so removed sites don't linger
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('DELETE FROM sites WHERE is_manual = 0')
            conn.commit()

        # Enrich sites concurrently
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(enrich_site, data, cloudns_zones, cloudns_cfg if cloudns_zones else None): domain
                for domain, data in all_sites.items()
            }
            with sqlite3.connect(DB_FILE) as conn:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        conn.execute('''
                            INSERT OR REPLACE INTO sites
                            (domain, name, hosting_provider, server_name, ip_address, ip_org,
                             registrar, expiry_date, nameservers, dns_provider,
                             notes, is_manual, last_updated)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            result['domain'],
                            result.get('name', ''),
                            result.get('hosting_provider', ''),
                            result.get('server_name', ''),
                            result.get('ip_address', ''),
                            result.get('ip_org', ''),
                            result.get('registrar', ''),
                            result.get('expiry_date', ''),
                            result.get('nameservers', '[]'),
                            result.get('dns_provider', ''),
                            result.get('notes', ''),
                            result.get('is_manual', 0),
                            result['last_updated'],
                        ))
                        conn.commit()
                    except Exception as e:
                        print(f'[Enrich] Error: {e}')
                    finally:
                        _refresh_state['progress'] += 1

        print(f'[Refresh] Done — {len(all_sites)} sites at {datetime.now():%Y-%m-%d %H:%M}')

    except Exception as e:
        _refresh_state['error'] = str(e)
        print(f'[Refresh] Fatal error: {e}')
    finally:
        _refresh_state['running'] = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows     = conn.execute('SELECT * FROM sites ORDER BY hosting_provider, domain').fetchall()
        latest   = conn.execute('SELECT MAX(last_updated) as lu FROM sites').fetchone()['lu']

    sites = []
    for r in rows:
        d = dict(r)
        d['nameservers'] = json.loads(d.get('nameservers') or '[]')
        # Expiry warning: days remaining
        if d.get('expiry_date'):
            try:
                remaining = (datetime.strptime(d['expiry_date'], '%Y-%m-%d') - datetime.now()).days
                d['expiry_days'] = remaining
            except Exception:
                d['expiry_days'] = None
        else:
            d['expiry_days'] = None
        sites.append(d)

    last_updated = datetime.fromtimestamp(latest).strftime('%d %b %Y, %H:%M') if latest else None

    providers = {}
    for s in sites:
        p = s['hosting_provider'] or 'Unknown'
        providers[p] = providers.get(p, 0) + 1

    return render_template(
        'index.html',
        sites=sites,
        last_updated=last_updated,
        providers=providers,
        total=len(sites),
        refresh_running=_refresh_state['running'],
    )


@app.route('/refresh', methods=['POST'])
def refresh():
    if not _refresh_state['running']:
        thread = threading.Thread(target=do_refresh, daemon=True)
        thread.start()
    return jsonify({'started': True})


@app.route('/refresh-status')
def refresh_status():
    return jsonify(_refresh_state)


@app.route('/add-site', methods=['POST'])
def add_site():
    domain = request.form.get('domain', '').strip().removeprefix('https://').removeprefix('http://')
    domain = domain.removeprefix('www.').rstrip('/').rstrip('.')
    name   = request.form.get('name', '').strip()
    host   = request.form.get('host', 'External').strip()
    notes  = request.form.get('notes', '').strip()

    if not domain:
        return redirect('/')

    # Persist in config
    config = load_config()
    config.setdefault('manual_sites', [])
    if not any(s.get('domain') == domain for s in config['manual_sites']):
        config['manual_sites'].append({
            'domain': domain,
            'name':   name or domain,
            'host':   host,
            'notes':  notes,
        })
        save_config(config)

    # Enrich and insert immediately (runs in request thread — shows spinner)
    cloudns_cfg   = config.get('cloudns', {})
    cloudns_zones = set()
    if cloudns_cfg.get('auth_id') and cloudns_cfg.get('auth_password'):
        cloudns_zones = fetch_cloudns_zones(cloudns_cfg)

    site_data = {
        'domain': domain, 'name': name or domain,
        'hosting_provider': host, 'server_name': '',
        'ip_address': '', 'notes': notes, 'is_manual': 1,
    }
    result = enrich_site(site_data, cloudns_zones, cloudns_cfg if cloudns_zones else None)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO sites
            (domain, name, hosting_provider, server_name, ip_address, ip_org,
             registrar, expiry_date, nameservers, dns_provider,
             notes, is_manual, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result['domain'], result.get('name', ''), result.get('hosting_provider', ''),
            result.get('server_name', ''), result.get('ip_address', ''), result.get('ip_org', ''),
            result.get('registrar', ''), result.get('expiry_date', ''),
            result.get('nameservers', '[]'), result.get('dns_provider', ''),
            result.get('notes', ''), 1, result['last_updated'],
        ))
        conn.commit()

    return redirect('/')


@app.route('/delete-site', methods=['POST'])
def delete_site():
    domain = request.form.get('domain', '').strip()
    if not domain:
        return redirect('/')

    config = load_config()
    config['manual_sites'] = [s for s in config.get('manual_sites', []) if s.get('domain') != domain]
    save_config(config)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('DELETE FROM sites WHERE domain = ?', (domain,))
        conn.commit()

    if request.headers.get('X-Requested-With') == 'fetch':
        return jsonify({'ok': True})
    return redirect('/')


# ---------------------------------------------------------------------------
# Single-site recheck
# ---------------------------------------------------------------------------

@app.route('/recheck-site', methods=['POST'])
def recheck_site():
    domain = request.json.get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'No domain provided'}), 400

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM sites WHERE domain = ?', (domain,)).fetchone()

    if not row:
        return jsonify({'ok': False, 'error': 'Domain not found'}), 404

    site_data = dict(row)
    site_data['nameservers'] = json.loads(site_data.get('nameservers') or '[]')

    config = load_config()
    cloudns_cfg = config.get('cloudns')
    try:
        cloudns_zones = set(fetch_cloudns_zones(cloudns_cfg)) if cloudns_cfg else set()
    except Exception:
        cloudns_zones = set()

    updated = enrich_site(site_data, cloudns_zones=cloudns_zones, cloudns_cfg=cloudns_cfg)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            UPDATE sites SET
                ip_address   = :ip_address,
                ip_org       = :ip_org,
                registrar    = :registrar,
                expiry_date  = :expiry_date,
                nameservers  = :nameservers,
                dns_provider = :dns_provider,
                last_updated = :last_updated
            WHERE domain = :domain
        ''', {**updated, 'nameservers': json.dumps(updated['nameservers'])})
        conn.commit()

    return jsonify({
        'ok': True,
        'ip_address':   updated['ip_address'],
        'ip_org':       updated['ip_org'],
        'registrar':    updated['registrar'],
        'expiry_date':  updated['expiry_date'],
        'dns_provider': updated['dns_provider'],
        'nameservers':  updated['nameservers'],
    })


# ---------------------------------------------------------------------------
# IP org backfill  (fills ip_org for rows that have an IP but no org yet)
# ---------------------------------------------------------------------------

def do_backfill_ip_orgs():
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT domain, ip_address FROM sites WHERE ip_address != '' AND (ip_org IS NULL OR ip_org = '')"
        ).fetchall()

    if not rows:
        print('[Backfill] Nothing to do.')
        return

    print(f'[Backfill] Looking up IP orgs for {len(rows)} sites…')
    done = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(lookup_ip_org, ip): domain for domain, ip in rows}
        with sqlite3.connect(DB_FILE) as conn:
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    org = future.result()
                    conn.execute('UPDATE sites SET ip_org = ? WHERE domain = ?', (org, domain))
                    conn.commit()
                    done += 1
                    if done % 20 == 0:
                        print(f'[Backfill] {done}/{len(rows)}…')
                except Exception as e:
                    print(f'[Backfill] Error for {domain}: {e}')

    print(f'[Backfill] Done — updated {done} sites.')


@app.route('/backfill-ip-orgs', methods=['POST'])
def backfill_ip_orgs():
    if not _refresh_state['running']:
        thread = threading.Thread(target=do_backfill_ip_orgs, daemon=True)
        thread.start()
    return jsonify({'started': True})


def do_backfill_registrars():
    global _backfill_state
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT domain FROM sites WHERE registrar IS NULL OR registrar = ''"
        ).fetchall()

    if not rows:
        print('[Registrar backfill] Nothing to do.')
        return

    domains = [r[0] for r in rows]
    _backfill_state = {'running': True, 'progress': 0, 'total': len(domains), 'filled': 0}
    print(f'[Registrar backfill] Looking up {len(domains)} domains…')

    with sqlite3.connect(DB_FILE) as conn:
        for i, domain in enumerate(domains, 1):
            # Skip if already filled since the job started
            current = conn.execute('SELECT registrar FROM sites WHERE domain = ?', (domain,)).fetchone()
            if current and current[0]:
                _backfill_state['progress'] = i
                continue
            try:
                registrar, expiry = lookup_whois(domain)
                if registrar or expiry:
                    conn.execute(
                        'UPDATE sites SET registrar = ?, expiry_date = ? WHERE domain = ?',
                        (registrar or '', expiry or '', domain)
                    )
                    conn.commit()
                    _backfill_state['filled'] += 1
            except Exception as e:
                print(f'[Registrar backfill] Error for {domain}: {e}')
            _backfill_state['progress'] = i
            time.sleep(1)

    print(f'[Registrar backfill] Done — {_backfill_state["filled"]}/{len(domains)} filled.')
    _backfill_state['running'] = False


@app.route('/backfill-registrars', methods=['POST'])
def backfill_registrars():
    if _backfill_state.get('running'):
        return jsonify({'started': False, 'already_running': True})
    thread = threading.Thread(target=do_backfill_registrars, daemon=True)
    thread.start()
    return jsonify({'started': True})


@app.route('/backfill-registrars-status')
def backfill_registrars_status():
    return jsonify(_backfill_state)


@app.route('/sync-teamwork', methods=['POST'])
def sync_teamwork():
    thread = threading.Thread(target=do_sync_teamwork, daemon=True)
    thread.start()
    return jsonify({'started': True})


# ---------------------------------------------------------------------------
# Uptime checker
# ---------------------------------------------------------------------------

_UPTIME_UA = (
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)

def check_uptime(domain):
    """Returns 'up', 'down', or 'unknown'. Tries HTTPS then HTTP."""
    apex = domain.removeprefix('www.')
    for scheme in ['https', 'http']:
        try:
            r = requests.get(
                f'{scheme}://{apex}',
                timeout=8,
                allow_redirects=True,
                stream=True,
                headers={'User-Agent': _UPTIME_UA},
            )
            # Read first 2 KB to detect real page vs error page
            chunk = next(r.iter_content(2048), b'')
            r.close()
            if r.status_code < 500:
                return 'up'
            # 5xx but with substantial HTML = site is up (Cloudways quirk)
            if len(chunk) > 500 and b'<html' in chunk.lower():
                return 'up'
            return 'down'
        except Exception:
            pass
    return 'down'


def do_check_uptime():
    global _uptime_state
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute('SELECT domain FROM sites ORDER BY domain').fetchall()

    domains = [r[0] for r in rows]
    _uptime_state = {'running': True, 'progress': 0, 'total': len(domains)}

    def _check_and_save(domain):
        status = check_uptime(domain)
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                'UPDATE sites SET uptime_status = ?, uptime_checked = ? WHERE domain = ?',
                (status, int(time.time()), domain)
            )
        return status

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_and_save, d): d for d in domains}
        for future in as_completed(futures):
            _uptime_state['progress'] += 1
            try:
                future.result()
            except Exception:
                pass

    _uptime_state['running'] = False
    print(f'[Uptime check] Done — {len(domains)} domains checked.')


@app.route('/check-uptime', methods=['POST'])
def check_uptime_route():
    if _uptime_state.get('running'):
        return jsonify({'started': False, 'already_running': True})
    thread = threading.Thread(target=do_check_uptime, daemon=True)
    thread.start()
    return jsonify({'started': True})


@app.route('/check-uptime-status')
def check_uptime_status():
    return jsonify(_uptime_state)


@app.route('/recheck-uptime', methods=['POST'])
def recheck_uptime_route():
    data = request.get_json(force=True)
    domain = (data or {}).get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'no domain'})
    status = check_uptime(domain)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            'UPDATE sites SET uptime_status=?, uptime_checked=? WHERE domain=?',
            (status, int(time.time()), domain)
        )
        conn.commit()
    return jsonify({'ok': True, 'status': status})


@app.route('/export.csv')
def export_csv():
    import csv, io
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM sites ORDER BY hosting_provider, domain').fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Domain', 'Name', 'Host', 'Server', 'IP', 'IP Org', 'DNS Provider',
                     'Registrar', 'Expiry', 'Uptime', 'Assignee', 'Notes'])
    for r in rows:
        writer.writerow([
            r['domain'], r['name'], r['hosting_provider'], r['server_name'],
            r['ip_address'], r['ip_org'], r['dns_provider'],
            r['registrar'], r['expiry_date'], r['uptime_status'],
            r['teamwork_assignee'], r['notes'],
        ])

    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=dnhq-hosting.csv'}
    )


# ---------------------------------------------------------------------------
# Email log (Elastic Email)
# ---------------------------------------------------------------------------

ELASTIC_BASE = 'https://api.elasticemail.com/v4'
AEST_OFFSET  = 10  # UTC+10 (AEST); AEDT is +11 but keeping simple

def _to_aest(utc_str):
    """Convert ISO UTC timestamp from Elastic Email to AEST with AM/PM."""
    if not utc_str:
        return ''
    try:
        from datetime import timedelta
        # Strip trailing Z or timezone info, keep first 19 chars
        clean = utc_str.rstrip('Z').split('+')[0][:19]
        dt = datetime.strptime(clean, '%Y-%m-%dT%H:%M:%S')
        dt_aest = dt + timedelta(hours=AEST_OFFSET)
        # Cross-platform: remove leading zeros manually
        day  = str(dt_aest.day)
        hour = dt_aest.hour % 12 or 12
        ampm = 'AM' if dt_aest.hour < 12 else 'PM'
        return f"{day} {dt_aest.strftime('%b %Y')}, {hour}:{dt_aest.strftime('%M')} {ampm}"
    except Exception:
        return utc_str[:16].replace('T', ' ')

EVENT_LABELS = {
    'Submission':    ('Submitted',  'bg-slate-100 text-slate-600'),
    'Sent':          ('Sent',       'bg-green-100 text-green-700'),
    'Opened':        ('Opened',     'bg-sky-100 text-sky-700'),
    'Clicked':       ('Clicked',    'bg-indigo-100 text-indigo-700'),
    'Bounced':       ('Bounced',    'bg-red-100 text-red-700'),
    'FailedAttempt': ('Failed',     'bg-orange-100 text-orange-700'),
    'Unsubscribed':  ('Unsub',      'bg-yellow-100 text-yellow-700'),
    'Complaint':     ('Complaint',  'bg-pink-100 text-pink-700'),
}

@app.route('/emails')
def email_log():
    cfg     = load_config()
    api_key = cfg.get('elasticemail', {}).get('api_key', '')

    # Filter params
    from_date  = request.args.get('from', '')
    to_date    = request.args.get('to', '')
    event_type = request.args.get('type', '')
    search     = request.args.get('q', '').strip().lower()
    page       = max(1, int(request.args.get('page', 1)))
    per_page   = 100

    params = {
        'limit':  per_page,
        'offset': (page - 1) * per_page,
        'orderBy': 'DateDescending',
    }
    if from_date:
        params['from'] = from_date + 'T00:00:00'
    if to_date:
        params['to']   = to_date + 'T23:59:59'
    if event_type:
        params['eventTypes'] = [event_type]

    events = []
    error  = None
    has_more = False

    if api_key:
        try:
            resp = requests.get(
                f'{ELASTIC_BASE}/events',
                headers={'X-ElasticEmail-ApiKey': api_key},
                params=params,
                timeout=15,
            )
            if resp.ok:
                raw = resp.json()
                for e in raw:
                    label, badge = EVENT_LABELS.get(e.get('EventType', ''), (e.get('EventType', '—'), 'bg-slate-100 text-slate-500'))
                    events.append({
                        'date':    _to_aest(e.get('EventDate', '')),
                        'from':    e.get('FromEmail', ''),
                        'to':      e.get('To', ''),
                        'subject': e.get('Subject', ''),
                        'type':    e.get('EventType', ''),
                        'label':   label,
                        'badge':   badge,
                        'msg_id':  e.get('MsgID', ''),
                        'message': e.get('Message', ''),
                    })
                has_more = len(raw) == per_page
            else:
                error = f'Elastic Email API error {resp.status_code}: {resp.text[:200]}'
        except Exception as exc:
            error = str(exc)
    else:
        error = 'No Elastic Email API key configured.'

    # Client-side search filter
    if search:
        events = [e for e in events if
                  search in e['to'].lower() or
                  search in e['from'].lower() or
                  search in e['subject'].lower()]

    return render_template(
        'emails.html',
        events=events,
        error=error,
        from_date=from_date,
        to_date=to_date,
        event_type=event_type,
        search=request.args.get('q', ''),
        page=page,
        has_more=has_more,
        event_types=list(EVENT_LABELS.keys()),
    )


@app.route('/email-detail/<path:msg_id>')
def email_detail(msg_id):
    cfg     = load_config()
    api_key = cfg.get('elasticemail', {}).get('api_key', '')
    if not api_key:
        return jsonify({'error': 'No Elastic Email API key configured.'})
    try:
        resp = requests.get(
            f'{ELASTIC_BASE}/emails/{msg_id}/view',
            headers={'X-ElasticEmail-ApiKey': api_key},
            timeout=15,
        )
        if not resp.ok:
            return jsonify({'error': f'API returned {resp.status_code}: {resp.text[:200]}'})
        data = resp.json()

        # v4 response: {"Preview": {"Body": "<html...>"}}
        preview  = data.get('Preview') or {}
        body_html = preview.get('Body') or ''

        # Parse any headers if present (v4 doesn't return them but handle gracefully)
        raw_headers = data.get('Headers') or {}
        if isinstance(raw_headers, dict):
            headers = [{'name': k, 'value': v} for k, v in raw_headers.items()]
        elif isinstance(raw_headers, list):
            headers = raw_headers
        else:
            headers = []

        return jsonify({
            'body_html': body_html,
            'body_text': '',   # v4 view endpoint only returns HTML
            'headers':   headers,
        })
    except Exception as exc:
        return jsonify({'error': str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# Ensure DB is initialised whether run directly or via gunicorn
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5050, use_reloader=False)
