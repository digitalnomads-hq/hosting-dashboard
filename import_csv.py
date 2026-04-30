"""
One-time import of ManageWP CSV export.
Skips: dnhq.com.au, digitalnomadshq.com.au, sg-host, kinsta.cloud,
       cloudwaysapps.com, and anything already in the database.
"""
import csv
import json
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Reuse helpers from app.py
from app import init_db, lookup_dns, lookup_whois, detect_dns_provider, DB_FILE

EXCLUDE_PATTERNS = [
    r'(^|\.)dnhq\.com\.au$',
    r'(^|\.)digitalnomadshq\.com\.au$',
    r'sg-host\.com',
    r'\.kinsta\.cloud$',
    r'cloudwaysapps\.com',
]

CSV_FILE = 'ManageWP History 2025.05.01-2025.12.01 (1).csv'


def clean_domain(url):
    url = re.sub(r'^https?://', '', url.strip().lower())
    return url.rstrip('/').removeprefix('www.')


def is_excluded(domain):
    return any(re.search(p, domain) for p in EXCLUDE_PATTERNS)


def existing_domains():
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute('SELECT domain FROM sites').fetchall()
    return {r[0] for r in rows}


def enrich(domain):
    ip, nameservers = lookup_dns(domain)
    registrar, expiry = lookup_whois(domain)
    return {
        'domain':           domain,
        'name':             domain,
        'hosting_provider': 'External',
        'server_name':      '',
        'ip_address':       ip or '',
        'registrar':        registrar or '',
        'expiry_date':      expiry or '',
        'nameservers':      json.dumps(nameservers),
        'dns_provider':     detect_dns_provider(nameservers),
        'notes':            'Imported from ManageWP',
        'is_manual':        1,
        'last_updated':     int(time.time()),
    }


def main():
    init_db()

    # Parse CSV
    seen, candidates = set(), []
    with open(CSV_FILE, newline='') as f:
        for row in csv.DictReader(f):
            domain = clean_domain(row.get('Site', ''))
            if not domain or domain in seen:
                continue
            seen.add(domain)
            if not is_excluded(domain):
                candidates.append(domain)

    # Remove already-known domains
    known = existing_domains()
    to_import = [d for d in candidates if d not in known]

    print(f"CSV unique domains : {len(seen)}")
    print(f"After exclusions   : {len(candidates)}")
    print(f"Already in DB      : {len(candidates) - len(to_import)}")
    print(f"New to import      : {len(to_import)}")

    if not to_import:
        print("Nothing new to import.")
        return

    print(f"\nRunning DNS + WHOIS lookups for {len(to_import)} domains (this may take a few minutes)…\n")

    done = 0
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(enrich, d): d for d in to_import}
        for future in as_completed(futures):
            done += 1
            try:
                result = future.result()
                results.append(result)
                print(f"  [{done}/{len(to_import)}] {result['domain']} — {result['ip_address'] or 'no IP'} / {result['dns_provider']}")
            except Exception as e:
                domain = futures[future]
                print(f"  [{done}/{len(to_import)}] {domain} — ERROR: {e}")

    # Bulk insert
    with sqlite3.connect(DB_FILE) as conn:
        conn.executemany('''
            INSERT OR IGNORE INTO sites
            (domain, name, hosting_provider, server_name, ip_address,
             registrar, expiry_date, nameservers, dns_provider,
             notes, is_manual, last_updated)
            VALUES (:domain, :name, :hosting_provider, :server_name, :ip_address,
                    :registrar, :expiry_date, :nameservers, :dns_provider,
                    :notes, :is_manual, :last_updated)
        ''', results)

    print(f"\nDone — imported {len(results)} sites into the dashboard.")


if __name__ == '__main__':
    main()
