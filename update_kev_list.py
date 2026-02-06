#!/usr/bin/env python3
"""
CISA KEV (Known Exploited Vulnerabilities) List Updater
========================================================
Downloads the latest CISA KEV catalog and saves it locally for use
with the weekly vulnerability report.

Usage:
    python update_kev_list.py [output_path]

Manual Download (if script fails due to network restrictions):
    1. Visit: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    2. Click "Download CSV" or "Download JSON"
    3. Save as 'kev_catalog.json' in the same folder as weekly_vuln_report.py

Alternative: GitHub mirror (same data, updated daily):
    https://github.com/cisagov/kev-data/blob/main/known_exploited_vulnerabilities.json
    (Click "Raw" then Save As)

The KEV catalog is updated by CISA regularly. Run this before generating
weekly reports to ensure you have the latest KEV data.
"""

import json
import sys
import os
from datetime import datetime

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
DEFAULT_OUTPUT = "kev_catalog.json"


def download_kev_catalog(output_path=None):
    """Download the CISA KEV catalog and save to a local file."""
    if output_path is None:
        output_path = DEFAULT_OUTPUT

    if not HAS_URLLIB:
        print("Error: urllib not available")
        return None

    # Try primary URL first, then GitHub mirror
    urls_to_try = [KEV_URL, GITHUB_URL]

    for url in urls_to_try:
        print(f"Trying: {url}")
        try:
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (KEV Updater)'})
            with urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            # Add metadata
            data['_metadata'] = {
                'downloaded_at': datetime.now().isoformat(),
                'source_url': url,
                'total_kevs': len(data.get('vulnerabilities', []))
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            kev_count = len(data.get('vulnerabilities', []))
            print(f"\nSuccess! Downloaded {kev_count:,} KEV entries")
            print(f"Saved to: {output_path}")
            return data

        except (HTTPError, URLError) as e:
            print(f"  Failed: {e}")
            continue
        except Exception as e:
            print(f"  Error: {e}")
            continue

    print("\n" + "="*60)
    print("MANUAL DOWNLOAD REQUIRED")
    print("="*60)
    print("Network restrictions prevented automatic download.")
    print("\nPlease download manually:")
    print(f"  1. Visit: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    print(f"  2. Click 'Download' and select JSON format")
    print(f"  3. Save as: {os.path.abspath(output_path)}")
    print("\nAlternatively, use the GitHub mirror:")
    print(f"  {GITHUB_URL}")
    print("="*60)
    return None


def load_kev_catalog(file_path=None):
    """Load KEV catalog from local file."""
    if file_path is None:
        file_path = DEFAULT_OUTPUT

    if not os.path.exists(file_path):
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading KEV catalog: {e}")
        return None


def get_kev_cve_set(kev_data):
    """Extract set of CVE IDs from KEV catalog for fast lookup."""
    if not kev_data or 'vulnerabilities' not in kev_data:
        return set()
    return {v['cveID'] for v in kev_data['vulnerabilities'] if 'cveID' in v}


def get_kev_details(kev_data):
    """Get detailed KEV info as a dict keyed by CVE ID."""
    if not kev_data or 'vulnerabilities' not in kev_data:
        return {}
    return {v['cveID']: v for v in kev_data['vulnerabilities'] if 'cveID' in v}


def check_catalog_freshness(file_path=None):
    """Check if KEV catalog exists and how old it is."""
    if file_path is None:
        file_path = DEFAULT_OUTPUT

    if not os.path.exists(file_path):
        return None, "File not found"

    data = load_kev_catalog(file_path)
    if not data:
        return None, "Could not load file"

    kev_count = len(data.get('vulnerabilities', []))

    if '_metadata' in data:
        try:
            downloaded_at = datetime.fromisoformat(data['_metadata']['downloaded_at'])
            age_days = (datetime.now() - downloaded_at).days
            return age_days, f"{kev_count:,} KEVs, {age_days} days old"
        except Exception:
            pass

    return 0, f"{kev_count:,} KEVs (age unknown)"


def main():
    output_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT

    # Check existing catalog
    age, status = check_catalog_freshness(output_path)
    if age is not None:
        print(f"Existing catalog: {status}")
        if age is not None and age < 1:
            print("Catalog is fresh (less than 1 day old).")
            response = input("Update anyway? [y/N]: ").strip().lower()
            if response != 'y':
                print("Keeping existing catalog.")
                return

    # Download
    result = download_kev_catalog(output_path)

    if result:
        # Show recent additions
        print("\n--- Recent KEV Additions ---")
        kevs = result.get('vulnerabilities', [])
        sorted_kevs = sorted(kevs, key=lambda x: x.get('dateAdded', ''), reverse=True)[:5]
        for kev in sorted_kevs:
            print(f"  {kev.get('cveID', 'N/A')}: {kev.get('vulnerabilityName', 'N/A')[:50]}")


if __name__ == "__main__":
    main()
