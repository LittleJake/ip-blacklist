#!/usr/bin/env python3
"""
IP Blacklist Updater
--------------------
Automates fetching, cleaning, validating, and merging public threat intelligence IP feeds.
Uses `cidr-merger` for high-performance CIDR aggregation and deduplication.
"""

import argparse
import concurrent.futures
import gzip
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Set

# Base directory (repository root)
BASE_DIR = Path(__file__).resolve().parent
CIDR_MERGER_PATH = BASE_DIR / "cidr-merger"

# Regex to detect potential IPv4/IPv6 addresses or CIDRs
IP_PATTERN = re.compile(r"([0-9a-fA-F:.]+(?:/\d+)?)")

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("blacklist-updater")

# Default HTTP request headers
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; IPBlacklistBot/2.0; +https://github.com/LittleJake/ip-blacklist)",
    "Accept": "text/plain,*/*",
}


def ensure_cidr_merger() -> Path:
    """Ensure cidr-merger binary exists and has execute permissions."""
    if not CIDR_MERGER_PATH.exists():
        raise FileNotFoundError(f"cidr-merger binary not found at {CIDR_MERGER_PATH}")
    if not os.access(CIDR_MERGER_PATH, os.X_OK):
        CIDR_MERGER_PATH.chmod(0o755)
    return CIDR_MERGER_PATH


def is_valid_public_ip_or_cidr(entry: str) -> bool:
    """
    Validate that entry is a valid IPv4/IPv6 network or address and is not private,
    loopback, link-local, multicast, or reserved.
    """
    try:
        net = ipaddress.ip_network(entry, strict=False)
        if (
            net.is_private
            or net.is_loopback
            or net.is_link_local
            or net.is_multicast
            or net.is_reserved
            or net.is_unspecified
        ):
            return False
        return True
    except ValueError:
        return False


def clean_and_extract_ips(text: str) -> List[str]:
    """Parse raw text response, strip comments, extract and validate public IP/CIDRs."""
    valid_ips: List[str] = []
    seen: Set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        # Strip trailing comments
        for sep in ("#", ";", "//"):
            if sep in line:
                line = line.split(sep, 1)[0].strip()

        match = IP_PATTERN.search(line)
        if not match:
            continue

        candidate = match.group(1).rstrip(".")
        if candidate in seen:
            continue

        if is_valid_public_ip_or_cidr(candidate):
            seen.add(candidate)
            valid_ips.append(candidate)

    return valid_ips


def fetch_url(url: str, headers: Optional[dict] = None, timeout: int = 15) -> str:
    """Fetch URL contents as string with timeout and error handling."""
    req_headers = dict(DEFAULT_HEADERS)
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="ignore")


def run_cidr_merger(input_files: List[Path], output_file: Path) -> bool:
    """Run ./cidr-merger on input files and write to output_file."""
    ensure_cidr_merger()
    cmd = [str(CIDR_MERGER_PATH), "-o", str(output_file)] + [str(p) for p in input_files]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        logger.error(f"cidr-merger failed for {output_file.name}: {result.stderr.strip()}")
        return False
    return True


# --- Source Fetchers ---

def fetch_abuseipdb(confidence: int, token: Optional[str]) -> List[str]:
    """Fetch AbuseIPDB blacklist for both IPv4 and IPv6."""
    if not token:
        logger.warning(f"ABUSEIPDB_TOKEN not provided, skipping AbuseIPDB (score {confidence}).")
        return []

    headers = {"Key": token, "Accept": "text/plain"}
    ips: List[str] = []

    for ip_ver in (4, 6):
        url = (
            f"https://api.abuseipdb.com/api/v2/blacklist"
            f"?ipVersion={ip_ver}&confidenceMinimum={confidence}&limit=9999999&plaintext"
        )
        try:
            raw_text = fetch_url(url, headers=headers, timeout=25)
            extracted = clean_and_extract_ips(raw_text)
            logger.info(f"AbuseIPDB (v{ip_ver}, score {confidence}): fetched {len(extracted)} IPs")
            ips.extend(extracted)
        except Exception as e:
            logger.warning(f"AbuseIPDB (v{ip_ver}, score {confidence}) fetch failed: {e}")

    return ips


def fetch_ustc() -> List[str]:
    """Fetch USTC blackip list."""
    url = "https://blackip.ustc.edu.cn/list.php?txt"
    raw_text = fetch_url(url, timeout=15)
    return clean_and_extract_ips(raw_text)


def fetch_neucert() -> List[str]:
    """Fetch NEUCERT legacy list (times out quickly if offline)."""
    url = "http://antivirus.neu.edu.cn/ssh/lists/neu.txt"
    raw_text = fetch_url(url, timeout=5)
    return clean_and_extract_ips(raw_text)


def fetch_blocklist_de() -> List[str]:
    """Fetch Blocklist.de all attack list."""
    url = "https://lists.blocklist.de/lists/all.txt"
    raw_text = fetch_url(url, timeout=20)
    return clean_and_extract_ips(raw_text)


def fetch_cinsscore() -> List[str]:
    """Fetch CINS Army Badguys list."""
    url = "https://cinsscore.com/list/ci-badguys.txt"
    raw_text = fetch_url(url, timeout=15)
    return clean_and_extract_ips(raw_text)


def fetch_feodotracker() -> List[str]:
    """Fetch abuse.ch Feodo Tracker Botnet C2 blocklist."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    raw_text = fetch_url(url, timeout=15)
    return clean_and_extract_ips(raw_text)


def fetch_emerging_threats() -> List[str]:
    """Fetch Emerging Threats compromised IPs."""
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    raw_text = fetch_url(url, timeout=15)
    return clean_and_extract_ips(raw_text)


def fetch_greensnow() -> List[str]:
    """Fetch GreenSnow threat list."""
    url = "https://blocklist.greensnow.co/greensnow.txt"
    raw_text = fetch_url(url, timeout=15)
    return clean_and_extract_ips(raw_text)


@dataclass
class ThreatSource:
    name: str
    filename: str
    fetch_fn: Callable[[], List[str]]
    description: str
    is_essential: bool = True  # If False, preserve existing file if fetch returns empty


def get_all_sources(abuseipdb_token: Optional[str]) -> List[ThreatSource]:
    return [
        ThreatSource(
            name="AbuseIPDB (Score 100)",
            filename="abuseipdb_blacklist_ip_score_100.txt",
            fetch_fn=lambda: fetch_abuseipdb(100, abuseipdb_token),
            description="AbuseIPDB Confidence 100%",
            is_essential=False,
        ),
        ThreatSource(
            name="AbuseIPDB (Score 75)",
            filename="abuseipdb_blacklist_ip_score_75.txt",
            fetch_fn=lambda: fetch_abuseipdb(75, abuseipdb_token),
            description="AbuseIPDB Confidence >= 75%",
            is_essential=False,
        ),
        ThreatSource(
            name="USTC",
            filename="ustc_blacklist_ip.txt",
            fetch_fn=fetch_ustc,
            description="University of Science and Technology of China Blacklist",
        ),
        ThreatSource(
            name="Blocklist.de",
            filename="blocklist_de.txt",
            fetch_fn=fetch_blocklist_de,
            description="Blocklist.de all attacking IPs (last 48h)",
        ),
        ThreatSource(
            name="CINS Army",
            filename="cinsscore_badguys.txt",
            fetch_fn=fetch_cinsscore,
            description="CINS Army Badguys List",
        ),
        ThreatSource(
            name="Feodo Tracker",
            filename="feodotracker_c2.txt",
            fetch_fn=fetch_feodotracker,
            description="abuse.ch Feodo Tracker Botnet C2",
        ),
        ThreatSource(
            name="Emerging Threats",
            filename="emerging_threats_compromised.txt",
            fetch_fn=fetch_emerging_threats,
            description="Proofpoint Emerging Threats Compromised IPs",
        ),
        ThreatSource(
            name="GreenSnow",
            filename="greensnow.txt",
            fetch_fn=fetch_greensnow,
            description="GreenSnow Honeypot Attack IP list",
        ),
        ThreatSource(
            name="NEUCERT",
            filename="neucert_blacklist_ip.txt",
            fetch_fn=fetch_neucert,
            description="Northeastern University CERT (Legacy / Offline)",
            is_essential=False,
        ),
    ]


def process_source(source: ThreatSource, temp_dir: Path) -> Optional[Path]:
    """Fetch, filter, and merge a threat source into its output file."""
    out_file = BASE_DIR / source.filename
    logger.info(f"Processing source: {source.name} -> {source.filename}")

    try:
        ips = source.fetch_fn()
    except Exception as e:
        logger.warning(f"Source '{source.name}' encountered an error: {e}")
        ips = []

    if not ips:
        if out_file.exists() and out_file.stat().st_size > 0:
            logger.warning(f"No new IPs retrieved for {source.name}. Keeping existing file {source.filename}.")
            return out_file
        elif not source.is_essential:
            logger.info(f"Optional source {source.name} empty or offline. Skipping.")
            return None
        else:
            logger.warning(f"Source {source.name} returned 0 IPs.")
            return None

    # Write raw IPs to temporary file
    raw_tmp = temp_dir / f"{source.filename}.raw.tmp"
    with open(raw_tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(ips) + "\n")

    # Run cidr-merger
    merged_tmp = temp_dir / f"{source.filename}.merged.tmp"
    if run_cidr_merger([raw_tmp], merged_tmp):
        shutil.move(str(merged_tmp), str(out_file))
        line_count = count_lines(out_file)
        logger.info(f"Successfully updated {source.filename} ({line_count} entries)")
        return out_file
    else:
        logger.error(f"Failed to merge CIDRs for {source.name}")
        return out_file if (out_file.exists() and out_file.stat().st_size > 0) else None


def count_lines(filepath: Path) -> int:
    """Count lines in text file."""
    if not filepath.exists():
        return 0
    with open(filepath, "rb") as f:
        return sum(1 for _ in f)


def build_all_blacklist(source_files: List[Path], temp_dir: Path) -> Path:
    """Merge all active individual blacklist files into all_blacklist.txt."""
    all_out = BASE_DIR / "all_blacklist.txt"
    logger.info("Building aggregated all_blacklist.txt from active feeds...")

    valid_sources = [f for f in source_files if f.exists() and f.stat().st_size > 0]
    if not valid_sources:
        logger.error("No valid source files available to build all_blacklist.txt!")
        return all_out

    merged_tmp = temp_dir / "all_blacklist.merged.tmp"
    if run_cidr_merger(valid_sources, merged_tmp):
        shutil.move(str(merged_tmp), str(all_out))
        total_lines = count_lines(all_out)
        logger.info(f"Updated all_blacklist.txt successfully ({total_lines} total unique entries).")
    else:
        logger.error("Failed to generate all_blacklist.txt")

    return all_out


def update_historical_append(all_blacklist_file: Path, temp_dir: Path) -> None:
    """Decompress historical append file, merge with new IPs, and recompress."""
    append_gz = BASE_DIR / "all_blacklist_append.txt.gz"
    logger.info("Updating historical cumulative file all_blacklist_append.txt.gz...")

    decompressed_tmp = temp_dir / "all_blacklist_append.decompressed.tmp"
    merged_tmp = temp_dir / "all_blacklist_append.merged.tmp"

    input_files: List[Path] = [all_blacklist_file]

    if append_gz.exists() and append_gz.stat().st_size > 0:
        logger.info("Decompressing existing all_blacklist_append.txt.gz...")
        try:
            with gzip.open(append_gz, "rb") as gz_in, open(decompressed_tmp, "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)
            input_files.append(decompressed_tmp)
        except Exception as e:
            logger.error(f"Failed to decompress {append_gz.name}: {e}")

    logger.info("Merging historical and current IPs via cidr-merger...")
    if run_cidr_merger(input_files, merged_tmp):
        # Compress with gzip level 9
        logger.info("Compressing updated cumulative blacklist with gzip...")
        with open(merged_tmp, "rb") as f_in, gzip.open(append_gz, "wb", compresslevel=9) as gz_out:
            shutil.copyfileobj(f_in, gz_out)
        gz_size_mb = append_gz.stat().st_size / (1024 * 1024)
        total_history_lines = count_lines(merged_tmp)
        logger.info(
            f"Successfully updated {append_gz.name} ({total_history_lines} unique IPs, {gz_size_mb:.2f} MB)"
        )
    else:
        logger.error("Failed to merge historical append file!")


def print_summary(sources: List[ThreatSource]) -> None:
    """Print markdown/table summary of generated blacklist files."""
    print("\n" + "=" * 60)
    print("BLACKISLIST UPDATE SUMMARY")
    print("=" * 60)
    for s in sources:
        path = BASE_DIR / s.filename
        lines = count_lines(path)
        print(f"  - {s.filename:<36} : {lines:>7} lines ({s.name})")

    all_file = BASE_DIR / "all_blacklist.txt"
    print(f"  - {'all_blacklist.txt':<36} : {count_lines(all_file):>7} lines (Current Active Merged)")

    append_gz = BASE_DIR / "all_blacklist_append.txt.gz"
    if append_gz.exists():
        size_mb = append_gz.stat().st_size / (1024 * 1024)
        print(f"  - {'all_blacklist_append.txt.gz':<36} : {size_mb:>6.2f} MB (Cumulative History)")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Update IP Blacklist feeds")
    parser.add_argument(
        "--skip-append",
        action="store_true",
        help="Skip updating all_blacklist_append.txt.gz to save time",
    )
    args = parser.parse_args()

    token = os.environ.get("ABUSEIPDB_TOKEN") or os.environ.get("ABUSEIPDB_KEY")
    sources = get_all_sources(token)

    with tempfile.TemporaryDirectory(prefix="ip_blacklist_") as tmpdir:
        temp_dir = Path(tmpdir)

        # Concurrently fetch and process sources
        active_source_files: List[Path] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_source = {
                executor.submit(process_source, src, temp_dir): src for src in sources
            }
            for future in concurrent.futures.as_completed(future_to_source):
                res_path = future.result()
                if res_path and res_path.exists() and res_path.stat().st_size > 0:
                    active_source_files.append(res_path)

        # Merge all active files into all_blacklist.txt
        all_blacklist_file = build_all_blacklist(active_source_files, temp_dir)

        # Update all_blacklist_append.txt.gz
        if not args.skip_append and all_blacklist_file.exists():
            update_historical_append(all_blacklist_file, temp_dir)

    print_summary(sources)


if __name__ == "__main__":
    main()
