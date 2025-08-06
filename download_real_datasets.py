#!/usr/bin/env python3
"""
Real Dataset Downloader - Downloads only accessible cybersecurity datasets
No API keys or registration required
"""

import requests
import zipfile
import io
import os
from datetime import datetime
import json

def download_openphish():
    """Download real phishing URLs from OpenPhish"""
    print("📥 Downloading OpenPhish real phishing URLs...")
    
    try:
        response = requests.get('https://openphish.com/feed.txt', timeout=30)
        if response.status_code == 200:
            os.makedirs('real_data', exist_ok=True)
            
            with open('real_data/openphish_urls.txt', 'w') as f:
                f.write(response.text)
            
            urls = [url.strip() for url in response.text.split('\n') if url.strip()]
            print(f"✅ Downloaded {len(urls)} real phishing URLs")
            return len(urls)
        else:
            print(f"❌ OpenPhish failed: Status {response.status_code}")
            return 0
            
    except Exception as e:
        print(f"❌ OpenPhish error: {e}")
        return 0

def download_tranco():
    """Download real top domains from Tranco"""
    print("📥 Downloading Tranco top 1M domains...")
    
    try:
        response = requests.get('https://tranco-list.eu/top-1m.csv.zip', timeout=60)
        if response.status_code == 200:
            os.makedirs('real_data', exist_ok=True)
            
            # Extract ZIP content
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                csv_files = [f for f in zip_file.namelist() if f.endswith('.csv')]
                if csv_files:
                    csv_content = zip_file.read(csv_files[0]).decode('utf-8')
                    
                    with open('real_data/tranco_domains.csv', 'w') as f:
                        f.write(csv_content)
                    
                    lines = [line for line in csv_content.split('\n') if line.strip()]
                    print(f"✅ Downloaded {len(lines)} real domain rankings")
                    return len(lines)
        
        print(f"❌ Tranco failed: Status {response.status_code}")
        return 0
        
    except Exception as e:
        print(f"❌ Tranco error: {e}")
        return 0

def test_urlhaus():
    """Test URLhaus access (best effort)"""
    print("🔍 Testing URLhaus access...")
    
    endpoints = [
        'https://urlhaus.abuse.ch/downloads/csv/',
        'https://urlhaus.abuse.ch/downloads/csv_recent/',
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, timeout=15)
            print(f"   {endpoint}: Status {response.status_code}")
            
            if response.status_code == 200:
                content = response.text[:1000]
                if 'url' in content.lower() and ('malware' in content.lower() or 'hash' in content.lower()):
                    os.makedirs('real_data', exist_ok=True)
                    with open('real_data/urlhaus_data.csv', 'w') as f:
                        f.write(response.text)
                    
                    lines = response.text.count('\n')
                    print(f"✅ Downloaded URLhaus data: {lines} lines")
                    return lines
                    
        except Exception as e:
            print(f"   Error: {e}")
    
    print("❌ URLhaus: No accessible data found")
    return 0

def create_download_summary():
    """Create summary of downloaded data"""
    summary = {
        'download_timestamp': datetime.now().isoformat(),
        'datasets_downloaded': [],
        'total_records': 0
    }
    
    # Check what was downloaded
    data_files = {
        'openphish_urls.txt': 'OpenPhish Phishing URLs',
        'tranco_domains.csv': 'Tranco Top Domains',
        'urlhaus_data.csv': 'URLhaus Malware URLs'
    }
    
    for filename, description in data_files.items():
        filepath = f'real_data/{filename}'
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                lines = len([line for line in f if line.strip()])
            
            summary['datasets_downloaded'].append({
                'name': description,
                'file': filename,
                'records': lines
            })
            summary['total_records'] += lines
    
    # Save summary
    with open('real_data/download_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary

def main():
    """Download all accessible real datasets"""
    print("="*60)
    print("REAL CYBERSECURITY DATASET DOWNLOADER")
    print("Downloading only verified accessible datasets")
    print("="*60)
    
    # Download each dataset
    openphish_count = download_openphish()
    tranco_count = download_tranco()
    urlhaus_count = test_urlhaus()
    
    # Create summary
    summary = create_download_summary()
    
    print("\n" + "="*60)
    print("DOWNLOAD SUMMARY")
    print("="*60)
    
    for dataset in summary['datasets_downloaded']:
        print(f"✅ {dataset['name']}: {dataset['records']:,} records")
    
    print(f"\n📊 Total Records Downloaded: {summary['total_records']:,}")
    print(f"📁 Data saved in: real_data/")
    print(f"📄 Summary: real_data/download_summary.json")
    
    if summary['total_records'] > 0:
        print("\n🎉 Ready for analysis! Run: python analyze_real_data.py")
    else:
        print("\n❌ No data downloaded. Check internet connection.")

if __name__ == "__main__":
    main()
