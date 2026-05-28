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
import hashlib
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, jsonify, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
if not os.environ.get('SECRET_KEY'):
    print('WARNING: SECRET_KEY not set — sessions will break with multiple workers. Set it as a Fly secret.')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'config.yaml')
# When deployed, DATA_DIR points to the persistent Fly.io volume (/data)
DATA_DIR  = os.environ.get('DATA_DIR', BASE_DIR)
DB_FILE   = os.path.join(DATA_DIR, 'sites.db')
CACHE_TTL = 86400  # 24 hours

_refresh_state   = {'running': False, 'progress': 0, 'total': 0, 'added': 0, 'error': None}
_refresh_lock    = threading.Lock()
_backfill_state  = {'running': False, 'progress': 0, 'total': 0, 'filled': 0}
_uptime_state    = {'running': False, 'progress': 0, 'total': 0}
_teamwork_state  = {'running': False, 'progress': 0, 'total': 0, 'added': 0}


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

    cfg['email_log_password'] = _env('EMAIL_LOG_PASSWORD', cfg.get('email_log_password', ''))

    return cfg


def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
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
        if 'is_stale' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN is_stale INTEGER DEFAULT 0')
        if 'date_added' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN date_added INTEGER DEFAULT 0')
        if 'hosting_created_at' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN hosting_created_at TEXT DEFAULT ""')
        if 'alt_domains' not in cols:
            conn.execute('ALTER TABLE sites ADD COLUMN alt_domains TEXT DEFAULT "[]"')

        # One-time: deduplicate and strip wildcards from stored alt_domains
        for row in conn.execute("SELECT domain, alt_domains FROM sites WHERE alt_domains IS NOT NULL AND alt_domains != '[]'").fetchall():
            try:
                raw = json.loads(row[1] or '[]')
                seen_d = set()
                cleaned = []
                for a in raw:
                    a = str(a).strip().removeprefix('www.').rstrip('.')
                    if a and not a.startswith('*.') and a not in seen_d:
                        cleaned.append(a)
                        seen_d.add(a)
                if cleaned != raw:
                    conn.execute('UPDATE sites SET alt_domains = ? WHERE domain = ?',
                                 (json.dumps(cleaned), row[0]))
            except Exception:
                pass

        # Remove any sites whose domain has no dot — these are bogus entries
        # created by the Teamwork sync matching bare task names like
        # "authority-building", "communication", "sales", etc.
        conn.execute("DELETE FROM sites WHERE domain NOT LIKE '%.%'")

        # Email events — permanent local history of all Elastic Email events
        conn.execute('''
            CREATE TABLE IF NOT EXISTS email_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id           TEXT NOT NULL,
                transaction_id   TEXT,
                from_email       TEXT,
                to_email         TEXT,
                subject          TEXT,
                event_type       TEXT,
                event_date       TEXT,
                channel_name     TEXT,
                message_category TEXT,
                message          TEXT,
                ip_address       TEXT,
                UNIQUE(msg_id, event_type, event_date)
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_ee_date ON email_events(event_date)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_ee_msg  ON email_events(msg_id)')
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
# Date helpers
# ---------------------------------------------------------------------------

def _parse_hosting_date(raw):
    """Parse a created_at string from Cloudways or Kinsta into a YYYY-MM-DD string.
    Handles ISO8601 (Kinsta) and MySQL datetime (Cloudways)."""
    if not raw:
        return ''
    for fmt in ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(raw[:26].rstrip('Z'), fmt.rstrip('Z')).strftime('%Y-%m-%d')
        except ValueError:
            continue
    return raw[:10]   # fallback: first 10 chars


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
                if not domain:
                    continue

                # Collect any alias/additional domains attached to this app
                seen = {domain}
                alt_domains = []
                all_aliases = list(app_data.get('aliases', []))
                for d_obj in app_data.get('app_domains', []):
                    raw = d_obj.get('domain', d_obj) if isinstance(d_obj, dict) else d_obj
                    all_aliases.append(str(raw))
                for alias in all_aliases:
                    a = str(alias).strip().removeprefix('www.').rstrip('.')
                    if (a and a not in seen
                            and not a.endswith('.cloudwaysapps.com')
                            and not a.startswith('*.')):
                        alt_domains.append(a)
                        seen.add(a)

                sites.append({
                    'domain':              domain,
                    'name':                app_data.get('label', domain),
                    'hosting_provider':    'Cloudways',
                    'server_name':         server_label,
                    'ip_address':          server_ip,
                    'is_manual':           0,
                    'hosting_created_at':  _parse_hosting_date(app_data.get('created_at', '')),
                    'alt_domains':         alt_domains,
                })
    except Exception as e:
        print(f'[Cloudways] Error: {e}')
    return sites


# ---------------------------------------------------------------------------
# Kinsta API
# ---------------------------------------------------------------------------

def _kinsta_site_domains(site_id, headers):
    """Fetch all live domains for a single Kinsta site.
    Returns (primary_domain, [alt_domains]) or (None, [])."""
    try:
        r = requests.get(f'https://api.kinsta.com/v2/sites/{site_id}', headers=headers, timeout=20)
        r.raise_for_status()
        for env in r.json().get('site', {}).get('environments', []):
            if env.get('name') == 'live' or env.get('display_name', '').lower() == 'live':
                seen = set()
                domains = []
                for d in env.get('domains', []):
                    name = d.get('name', '') if isinstance(d, dict) else str(d)
                    clean = name.removeprefix('www.').rstrip('.')
                    if (clean and clean not in seen
                            and not clean.endswith('.kinsta.cloud')
                            and not clean.startswith('*.')):
                        domains.append(clean)
                        seen.add(clean)
                if domains:
                    return domains[0], domains[1:]
    except Exception as e:
        print(f'[Kinsta] Error fetching site {site_id}: {e}')
    return None, []


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
                ex.submit(_kinsta_site_domains, s['id'], headers): s
                for s in site_list
            }
            for future, site in future_to_site.items():
                primary, alts = future.result()
                if primary:
                    sites.append({
                        'domain':              primary,
                        'name':                site.get('display_name') or site.get('name', primary),
                        'hosting_provider':    'Kinsta',
                        'server_name':         '',
                        'ip_address':          '',
                        'is_manual':           0,
                        'hosting_created_at':  _parse_hosting_date(site.get('created_at', '')),
                        'alt_domains':         alts,
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
    domain = url.rstrip('/').removeprefix('www.').split('/')[0]
    # Must contain a dot to be a real domain (filters bare words like
    # "authority-building", "communication", "sales", etc.)
    return domain if '.' in domain else ''


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
    global _teamwork_state
    _teamwork_state = {'running': True, 'progress': 0, 'total': 0, 'added': 0}

    config = load_config()
    tw_cfg = config.get('teamwork', {})
    if not tw_cfg:
        print('[Teamwork sync] No teamwork config found.')
        _teamwork_state['running'] = False
        return

    print('[Teamwork sync] Fetching tasks…')
    try:
        domain_map = fetch_teamwork_tasks(tw_cfg)
    except Exception as e:
        print(f'[Teamwork sync] Failed to fetch tasks: {e}')
        _teamwork_state['running'] = False
        return

    print(f'[Teamwork sync] Found {len(domain_map)} domain tasks')
    _teamwork_state['total'] = len(domain_map)

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute('SELECT domain, alt_domains FROM sites').fetchall()

    # Build reverse lookup: every domain (primary + alts) → primary domain in DB
    domain_to_primary = {}
    for primary, alt_json in rows:
        domain_to_primary[primary] = primary
        for alt in json.loads(alt_json or '[]'):
            domain_to_primary[alt.strip().removeprefix('www.').rstrip('.')] = primary

    existing_primaries = set(domain_to_primary.values())

    with sqlite3.connect(DB_FILE) as conn:
        # Clear existing teamwork data
        conn.execute('UPDATE sites SET teamwork_task_id = "", teamwork_assignee = ""')
        matched = 0
        new_domains = []

        for domain, info in domain_map.items():
            # Check exact match first, then check if it's an alt domain of a known site
            primary = domain_to_primary.get(domain)
            if primary:
                conn.execute(
                    'UPDATE sites SET teamwork_task_id = ?, teamwork_assignee = ? WHERE domain = ?',
                    (info['task_id'], info['assignee'], primary)
                )
                matched += 1
            else:
                new_domains.append((domain, info))
            _teamwork_state['progress'] += 1

        conn.commit()

    print(f'[Teamwork sync] Matched {matched}/{len(domain_map)} — enriching {len(new_domains)} new domains…')

    added = 0
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
            added += 1
            print(f'[Teamwork sync] Added {domain} ({info["assignee"]})')
            time.sleep(1)
        except Exception as e:
            print(f'[Teamwork sync] Failed to add {domain}: {e}')

    _teamwork_state['added'] = added
    _teamwork_state['running'] = False
    print(f'[Teamwork sync] Done — {matched} matched, {added} added.')


# ---------------------------------------------------------------------------
# Fetch sites (Cloudways + Kinsta only — fast, no DNS/WHOIS enrichment)
# ---------------------------------------------------------------------------

def do_refresh():
    """Pull domains from Cloudways and Kinsta, INSERT new ones, update metadata on
    existing ones.  Never deletes rows — DNS/WHOIS enrichment is done separately."""
    global _refresh_state
    with _refresh_lock:
        if _refresh_state['running']:
            return
        _refresh_state = {'running': True, 'progress': 0, 'total': 0, 'added': 0, 'error': None}

    try:
        config   = load_config()
        fetched  = {}

        # --- Cloudways ---
        cw = config.get('cloudways', {})
        if cw.get('email') and cw.get('api_key'):
            for s in fetch_cloudways_sites(cw):
                fetched[s['domain']] = s

        # --- Kinsta ---
        ki = config.get('kinsta', {})
        if ki.get('api_key'):
            for s in fetch_kinsta_sites(ki):
                if s['domain'] not in fetched:
                    fetched[s['domain']] = s

        _refresh_state['total'] = len(fetched)
        added = 0
        now = int(time.time())

        with sqlite3.connect(DB_FILE) as conn:
            for domain, site in fetched.items():
                hosting_created = site.get('hosting_created_at', '')
                alt_domains_json = json.dumps(site.get('alt_domains', []))
                cur = conn.execute('''
                    INSERT OR IGNORE INTO sites
                    (domain, name, hosting_provider, server_name, ip_address,
                     is_manual, is_stale, date_added, hosting_created_at, alt_domains, last_updated)
                    VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)
                ''', (
                    site['domain'],
                    site.get('name', domain),
                    site.get('hosting_provider', ''),
                    site.get('server_name', ''),
                    site.get('ip_address', ''),
                    now, hosting_created, alt_domains_json, now,
                ))
                if cur.rowcount:
                    added += 1
                else:
                    # Update hosting metadata; clear stale flag; refresh creation date and alt domains
                    conn.execute('''
                        UPDATE sites
                        SET name = ?, hosting_provider = ?, server_name = ?, ip_address = ?,
                            is_stale = 0,
                            alt_domains = ?,
                            hosting_created_at = CASE WHEN ? != '' THEN ? ELSE hosting_created_at END
                        WHERE domain = ? AND is_manual = 0
                    ''', (
                        site.get('name', domain),
                        site.get('hosting_provider', ''),
                        site.get('server_name', ''),
                        site.get('ip_address', ''),
                        alt_domains_json,
                        hosting_created, hosting_created,
                        domain,
                    ))
                _refresh_state['progress'] += 1

            # Mark any previously-tracked Cloudways/Kinsta site that's no longer in
            # the API response as stale (don't delete — just flag it)
            if fetched:
                placeholders = ','.join('?' * len(fetched))
                conn.execute(f'''
                    UPDATE sites
                    SET is_stale = 1
                    WHERE is_manual = 0
                      AND hosting_provider IN ('Cloudways', 'Kinsta')
                      AND domain NOT IN ({placeholders})
                ''', list(fetched.keys()))

            # Mark any site whose domain is now known to be an alt domain of
            # another site as stale — e.g. a Teamwork-synced row for
            # werlemanproperty.com.au when it's really an alias of
            # werlemanbuyersagents.com.au
            all_alt_domains = set()
            for s in fetched.values():
                for a in s.get('alt_domains', []):
                    all_alt_domains.add(a)
            if all_alt_domains:
                placeholders2 = ','.join('?' * len(all_alt_domains))
                conn.execute(f'''
                    UPDATE sites SET is_stale = 1
                    WHERE domain IN ({placeholders2})
                      AND domain NOT IN ({','.join('?' * len(fetched))})
                ''', list(all_alt_domains) + list(fetched.keys()))

            conn.commit()

        _refresh_state['added'] = added
        print(f'[Fetch Sites] Done — {added} new, {len(fetched) - added} updated at {datetime.now():%Y-%m-%d %H:%M}')

    except Exception as e:
        _refresh_state['error'] = str(e)
        print(f'[Fetch Sites] Fatal error: {e}')
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
        d['alt_domains'] = json.loads(d.get('alt_domains') or '[]')
        # Expiry warning: days remaining
        if d.get('expiry_date'):
            try:
                remaining = (datetime.strptime(d['expiry_date'], '%Y-%m-%d') - datetime.now()).days
                d['expiry_days'] = remaining
            except Exception:
                d['expiry_days'] = None
        else:
            d['expiry_days'] = None

        # Format date_added (dashboard tracking) for display
        ts = d.get('date_added') or 0
        if ts:
            dt = datetime.fromtimestamp(ts)
            d['date_added_str'] = f"{dt.day} {dt.strftime('%b %Y')}"
        else:
            d['date_added_str'] = ''

        # Format uptime_checked timestamp for tooltip display
        uc = d.get('uptime_checked') or 0
        if uc:
            udt = datetime.fromtimestamp(uc)
            hour = udt.hour % 12 or 12
            ampm = 'AM' if udt.hour < 12 else 'PM'
            d['uptime_checked_str'] = f"{udt.day} {udt.strftime('%b %Y')}, {hour}:{udt.strftime('%M')} {ampm}"
        else:
            d['uptime_checked_str'] = ''

        # Format hosting_created_at (date created on Cloudways/Kinsta) for display & sort
        hca = (d.get('hosting_created_at') or '').strip()
        if hca:
            try:
                hdt = datetime.strptime(hca, '%Y-%m-%d')
                d['hosting_created_str'] = f"{hdt.day} {hdt.strftime('%b %Y')}"
                d['hosting_created_sort'] = hca   # YYYY-MM-DD sorts lexicographically
            except Exception:
                d['hosting_created_str'] = hca
                d['hosting_created_sort'] = hca
        else:
            d['hosting_created_str'] = ''
            d['hosting_created_sort'] = ''

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
    )


@app.route('/refresh', methods=['POST'])
def refresh():
    """Run the fetch synchronously and return the result directly.
    This avoids state-loss when Fly.io auto-stops the machine between the
    POST and the polling requests."""
    if _refresh_state['running']:
        return jsonify({'already_running': True})
    do_refresh()   # blocks until done (Cloudways+Kinsta only, typically <15s)
    return jsonify({**_refresh_state, 'done': True})


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
            INSERT INTO sites
            (domain, name, hosting_provider, server_name, ip_address, ip_org,
             registrar, expiry_date, nameservers, dns_provider,
             notes, is_manual, date_added, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                name             = excluded.name,
                hosting_provider = excluded.hosting_provider,
                server_name      = excluded.server_name,
                ip_address       = excluded.ip_address,
                ip_org           = excluded.ip_org,
                registrar        = excluded.registrar,
                expiry_date      = excluded.expiry_date,
                nameservers      = excluded.nameservers,
                dns_provider     = excluded.dns_provider,
                notes            = excluded.notes,
                is_manual        = 1,
                last_updated     = excluded.last_updated
        ''', (
            result['domain'], result.get('name', ''), result.get('hosting_provider', ''),
            result.get('server_name', ''), result.get('ip_address', ''), result.get('ip_org', ''),
            result.get('registrar', ''), result.get('expiry_date', ''),
            result.get('nameservers', '[]'), result.get('dns_provider', ''),
            result.get('notes', ''), int(time.time()), result['last_updated'],
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
        ''', {**updated, 'nameservers': updated.get('nameservers', '[]')})
        conn.commit()

    # enrich_site returns nameservers as a JSON string; parse it back for the API response
    ns = updated.get('nameservers', '[]')
    if isinstance(ns, str):
        try:
            ns = json.loads(ns)
        except Exception:
            ns = []

    return jsonify({
        'ok': True,
        'ip_address':   updated['ip_address'],
        'ip_org':       updated['ip_org'],
        'registrar':    updated['registrar'],
        'expiry_date':  updated['expiry_date'],
        'dns_provider': updated['dns_provider'],
        'nameservers':  ns,
    })



def do_fill_details():
    """Enrich every site with DNS, WHOIS, and IP org data.
    Skips fields that are already filled to avoid redundant lookups."""
    global _backfill_state

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute('SELECT domain, ip_address FROM sites').fetchall()

    if not rows:
        print('[Fill Details] Nothing to do.')
        return

    _backfill_state = {'running': True, 'progress': 0, 'total': len(rows), 'filled': 0}
    print(f'[Fill Details] Enriching {len(rows)} sites…')

    config = load_config()
    cloudns_cfg = config.get('cloudns', {})
    cloudns_zones = set()
    if cloudns_cfg.get('auth_id') and cloudns_cfg.get('auth_password'):
        try:
            cloudns_zones = fetch_cloudns_zones(cloudns_cfg)
            print(f'[Fill Details] ClouDNS zones: {len(cloudns_zones)}')
        except Exception:
            pass

    with sqlite3.connect(DB_FILE) as conn:
        for i, (domain, existing_ip) in enumerate(rows, 1):
            try:
                apex = domain.removeprefix('www.')
                in_cloudns = apex in cloudns_zones

                # --- DNS / IP ---
                if in_cloudns and cloudns_cfg:
                    ip = fetch_cloudns_a_record(apex, cloudns_cfg) or existing_ip or ''
                else:
                    ip = existing_ip or ''

                dns_ip, nameservers = lookup_dns(domain)
                if not ip:
                    ip = dns_ip or ''

                dns_provider = 'ClouDNS' if in_cloudns else detect_dns_provider(nameservers)

                # --- WHOIS ---
                registrar, expiry = lookup_whois(apex)

                # --- IP org ---
                ip_org = lookup_ip_org(ip) if ip else ''

                conn.execute('''
                    UPDATE sites SET
                        ip_address   = ?,
                        ip_org       = ?,
                        nameservers  = ?,
                        dns_provider = ?,
                        registrar    = ?,
                        expiry_date  = ?,
                        last_updated = ?
                    WHERE domain = ?
                ''', (
                    ip, ip_org, json.dumps(nameservers), dns_provider,
                    registrar or '', expiry or '',
                    int(time.time()), domain,
                ))
                conn.commit()
                _backfill_state['filled'] += 1
            except Exception as e:
                print(f'[Fill Details] Error for {domain}: {e}')
            _backfill_state['progress'] = i
            time.sleep(0.5)

    print(f'[Fill Details] Done — {_backfill_state["filled"]}/{len(rows)} enriched.')
    _backfill_state['running'] = False


@app.route('/backfill-registrars', methods=['POST'])
def backfill_registrars():
    if _backfill_state.get('running'):
        return jsonify({'started': False, 'already_running': True})
    thread = threading.Thread(target=do_fill_details, daemon=True)
    thread.start()
    return jsonify({'started': True})


@app.route('/backfill-registrars-status')
def backfill_registrars_status():
    return jsonify(_backfill_state)


@app.route('/sync-teamwork', methods=['POST'])
def sync_teamwork():
    if _teamwork_state.get('running'):
        return jsonify({'started': False, 'already_running': True})
    thread = threading.Thread(target=do_sync_teamwork, daemon=True)
    thread.start()
    return jsonify({'started': True})


@app.route('/sync-teamwork-status')
def sync_teamwork_status():
    return jsonify(_teamwork_state)


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
# Email log auth
# ---------------------------------------------------------------------------

def require_email_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('email_log_authed'):
            return redirect(url_for('email_login', next=request.url))
        return f(*args, **kwargs)
    return decorated


@app.route('/email-login', methods=['GET', 'POST'])
def email_login():
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        cfg = load_config()
        correct = cfg.get('email_log_password', '')
        # Constant-time comparison to prevent timing attacks
        if correct and secrets.compare_digest(password.encode(), correct.encode()):
            session['email_log_authed'] = True
            next_url = request.args.get('next') or ''
            if not next_url or not next_url.startswith('/'):
                next_url = url_for('email_log')
            return redirect(next_url)
        error = 'Incorrect password.'
    return render_template('email_login.html', error=error)


@app.route('/email-logout')
def email_logout():
    session.pop('email_log_authed', None)
    return redirect(url_for('email_login'))


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

# Event priority — used to pick the "headline" status when grouping
EVENT_PRIORITY = ['Bounced', 'Complaint', 'Unsubscribed', 'Clicked', 'Opened', 'Sent', 'FailedAttempt', 'Submission']

def _sync_email_events(api_key):
    """Fetch the latest 500 events from Elastic Email and save new ones to the local DB.
    Returns (number_inserted, error_string_or_None)."""
    try:
        resp = requests.get(
            f'{ELASTIC_BASE}/events',
            headers={'X-ElasticEmail-ApiKey': api_key},
            params={'limit': 500, 'offset': 0, 'orderBy': 'DateDescending'},
            timeout=20,
        )
        if not resp.ok:
            return 0, f'API error {resp.status_code}: {resp.text[:200]}'

        raw = resp.json()
        inserted = 0
        with sqlite3.connect(DB_FILE) as conn:
            for e in raw:
                mid = e.get('MsgID') or e.get('TransactionID', '')
                cur = conn.execute('''
                    INSERT OR IGNORE INTO email_events
                    (msg_id, transaction_id, from_email, to_email, subject,
                     event_type, event_date, channel_name, message_category,
                     message, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mid,
                    e.get('TransactionID', ''),
                    e.get('FromEmail', ''),
                    e.get('To', ''),
                    e.get('Subject', ''),
                    e.get('EventType', ''),
                    e.get('EventDate', ''),
                    e.get('ChannelName', ''),
                    e.get('MessageCategory', ''),
                    e.get('Message', ''),
                    e.get('IPAddress', ''),
                ))
                inserted += cur.rowcount
            conn.commit()
        return inserted, None
    except Exception as exc:
        return 0, str(exc)


def _build_email_rows_from_db(from_date='', to_date='', search=''):
    """Load email events from local DB, group by msg_id, return sorted display rows."""
    where, params = [], []

    if from_date:
        where.append('event_date >= ?')
        params.append(from_date + 'T00:00:00')
    if to_date:
        where.append('event_date <= ?')
        params.append(to_date + 'T23:59:59')
    if search:
        where.append('(LOWER(to_email) LIKE ? OR LOWER(from_email) LIKE ? OR LOWER(subject) LIKE ?)')
        params += [f'%{search}%', f'%{search}%', f'%{search}%']

    where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f'SELECT * FROM email_events {where_sql} ORDER BY event_date ASC',
            params,
        ).fetchall()

    # Group by msg_id
    groups = {}
    for row in rows:
        mid = row['msg_id']
        if mid not in groups:
            groups[mid] = []
        groups[mid].append(dict(row))

    emails = []
    for mid, evts in groups.items():
        evts_sorted = sorted(evts, key=lambda x: x.get('event_date', ''))
        first  = evts_sorted[0]
        latest = evts_sorted[-1]

        seen_types, event_types_ordered = set(), []
        for ev in evts_sorted:
            t = ev.get('event_type', '')
            if t and t not in seen_types:
                seen_types.add(t)
                event_types_ordered.append(t)

        headline_type = next(
            (t for t in EVENT_PRIORITY if t in seen_types),
            event_types_ordered[-1] if event_types_ordered else ''
        )
        headline_label, headline_badge = EVENT_LABELS.get(
            headline_type, (headline_type, 'bg-slate-100 text-slate-500')
        )

        detail_msg = next(
            (ev.get('message', '') for ev in evts_sorted
             if ev.get('event_type') in ('Bounced', 'FailedAttempt') and ev.get('message')),
            ''
        )

        timeline = [
            {
                'type':  t,
                'label': EVENT_LABELS.get(t, (t, ''))[0],
                'badge': EVENT_LABELS.get(t, ('', 'bg-slate-100 text-slate-500'))[1],
            }
            for t in event_types_ordered
        ]

        emails.append({
            'msg_id':         mid,
            'date':           _to_aest(first.get('event_date', '')),
            'date_raw':       first.get('event_date', ''),
            'from':           first.get('from_email', ''),
            'to':             first.get('to_email', ''),
            'subject':        first.get('subject', ''),
            'channel':        first.get('channel_name', ''),
            'category':       first.get('message_category', ''),
            'ip':             latest.get('ip_address', ''),
            'headline_label': headline_label,
            'headline_badge': headline_badge,
            'headline_type':  headline_type,
            'timeline':       timeline,
            'message':        detail_msg,
            'opens':          sum(1 for ev in evts if ev.get('event_type') == 'Opened'),
            'clicks':         sum(1 for ev in evts if ev.get('event_type') == 'Clicked'),
        })

    emails.sort(key=lambda x: x['date_raw'], reverse=True)
    return emails


@app.route('/emails')
@require_email_auth
def email_log():
    cfg     = load_config()
    api_key = cfg.get('elasticemail', {}).get('api_key', '')

    from_date = request.args.get('from', '')
    to_date   = request.args.get('to', '')
    search    = request.args.get('q', '').strip().lower()
    page      = max(1, int(request.args.get('page', 1)))
    per_page  = 100

    error    = None
    synced   = 0

    # Always sync latest from API on page load — new events are INSERT OR IGNORE'd
    if api_key:
        synced, sync_err = _sync_email_events(api_key)
        if sync_err:
            error = f'Sync warning: {sync_err}'
    else:
        error = 'No Elastic Email API key configured.'

    # Load all matching events from local DB (includes full history)
    all_emails = _build_email_rows_from_db(from_date, to_date, search)

    # Pagination over grouped results
    total    = len(all_emails)
    start    = (page - 1) * per_page
    has_more = total > start + per_page
    emails   = all_emails[start:start + per_page]

    # Count total stored events for display
    with sqlite3.connect(DB_FILE) as conn:
        total_stored = conn.execute('SELECT COUNT(*) FROM email_events').fetchone()[0]

    return render_template(
        'emails.html',
        emails=emails,
        error=error,
        from_date=from_date,
        to_date=to_date,
        search=request.args.get('q', ''),
        page=page,
        has_more=has_more,
        synced=synced,
        total_stored=total_stored,
        total_filtered=total,
    )


@app.route('/email-detail/<path:msg_id>')
@require_email_auth
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
