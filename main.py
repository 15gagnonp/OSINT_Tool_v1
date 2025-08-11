#!/usr/bin/env python3

import os
import sys
import time
import json
import argparse
import re
import ipaddress
from dotenv import load_dotenv
import requests

# Load environment variables as global variable API_KEY (pulled from .env file) 
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
# VirusTotal API endpoints
VT_URLS = {
    "ip": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "domain": "https://www.virustotal.com/api/v3/domains/{}"
}

headers = {
    "x-apikey": API_KEY
}


def check_api_key():
    if not API_KEY:
        print("Error: VirusTotal API key not found in environment variables.")
        sys.exit(1)

# Load config
def load_config():
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
            return config.get("rate_limit_per_minute", 4)
    except Exception as e:
        print(f"Error loading config.json: {e}")
        sys.exit(1)

# Argument parsing (pending verification)
def parse_arguments(): 
    parser = argparse.ArgumentParser(description="VirusTotal IP/Domain Lookup Script")
    parser.add_argument("--input", required=True, help="Input file with IPs or domains")
    parser.add_argument("--type", required=True, choices=["ip", "domain"], help="Type of input: ip or domain")
    args = parser.parse_args()
    return args

# Input validation functions
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    # Simple regex for domain validation
    # This might not reflect all valid domain formats, but might covers common case
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$"
    return re.match(pattern, domain) is not None

# Read and validate input
def read_and_validate_input():
    args = parse_arguments()
    with open(args.input, "r") as f:
        entries = [line.strip() for line in f if line.strip()]

    if args.type == "ip":
        valid_entries = [e for e in entries if is_valid_ip(e)]
        invalid_entries = [e for e in entries if not is_valid_ip(e)]
    elif args.type == "domain":
        valid_entries = [e for e in entries if is_valid_domain(e)]
        invalid_entries = [e for e in entries if not is_valid_domain(e)]

    if invalid_entries:
        print("Warning: The following entries are invalid and will be skipped:")
        for entry in invalid_entries:
            print(f"  {entry}")
    return valid_entries, invalid_entries

    if not valid_entries:
        print("No valid entries to process.")
        sys.exit(0)

def convert_epoch_to_date(epoch):
    """Convert epoch time to human-readable date."""
    if not epoch:
        return "N/A"
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))
    except Exception as e:
        print(f"Error converting epoch {epoch}: {e}")
        return "N/A"

def query_virustotal(entry, entry_type):
    url = VT_URLS[entry_type].format(entry)
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 429:
            print("Rate limit exceeded. Waiting before retrying...")
            time.sleep(60)
            return query_virustotal(entry, entry_type)
        elif resp.status_code != 200:
            print(f"Error querying {entry}: HTTP {resp.status_code}")
            return None
        return resp.json()
    except requests.RequestException as e:
        print(f"Network error for {entry}: {e}")
        return None

# Main processing loop
def main(RATE_LIMIT):
    print(r"""
   
██╗   ██╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║   ██║╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║   ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚██╗ ██╔╝   ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚████╔╝    ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═══╝     ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

═══════════════════════════════════════════════════════════════
            VirusTotal OSINT Reconnaissance Tool
═══════════════════════════════════════════════════════════════ 
    """)
    # read and validate input from file
    valid_invalid = read_and_validate_input()
    # parse argurments from user input (file and type) 
    args = parse_arguments()
    interval = 60 / RATE_LIMIT
    for entry in valid_invalid[0]: 
        data = query_virustotal(entry, args.type)
        if not data:
            print(f"Failed to retrieve data for {entry}")
            time.sleep(interval)
            continue

        attr = data.get("data", {}).get("attributes", {})
        score = attr.get("last_analysis_stats", {})
        community_score = attr.get("reputation", "N/A")

        # Add score and count malicious/suspicious out of total
        Total = score.get('malicious', 1) + score.get('suspicious', 1) + score.get('undetected', 1) + score.get('harmless',1)
        mal_sus = score.get('malicious', 1) + score.get('suspicious', 1) 

        print(f"\n OSINT on {entry}: {mal_sus}/{Total} malicious hits")
        print(f"  Community Score: {community_score}")

        if args.type == "domain":
            reg_date = attr.get("creation_date", "N/A")
            reg_date = convert_epoch_to_date(reg_date)
            print(f"  Registered: {reg_date}")
        elif args.type == "ip":
            location = attr.get("country", "N/A")
            print(f"  Location: {location}")
        # to avoid hitting the Virus Total API rate limit
        time.sleep(interval)

# load Rate_limit from config and set global variable
RATE_LIMIT = load_config() 
# Check API key before proceeding
check_api_key()
# check config file for rate limit
load_config()
# Initialize the script
main(RATE_LIMIT)