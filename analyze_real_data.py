#!/usr/bin/env python3
"""
Real Data Analyzer - Analyzes downloaded cybersecurity datasets
Provides metrics for timeliness, quality, and research suitability
"""

import json
import os
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter
import pandas as pd

class RealDataAnalyzer:
    """Analyzes real cybersecurity datasets"""
    
    def __init__(self):
        self.results = {}
        
    def analyze_openphish(self):
        """Analyze OpenPhish phishing URLs"""
        print("🔍 Analyzing OpenPhish data...")
        
        filepath = 'real_data/openphish_urls.txt'
        if not os.path.exists(filepath):
            return {'success': False, 'error': 'OpenPhish data not found'}
        
        with open(filepath, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        # Real analysis
        domains = []
        tlds = []
        protocols = {'http': 0, 'https': 0}
        paths = {'root': 0, 'deep': 0}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domains.append(parsed.netloc)
                
                if parsed.scheme in protocols:
                    protocols[parsed.scheme] += 1
                
                if '.' in parsed.netloc:
                    tld = parsed.netloc.split('.')[-1]
                    tlds.append(tld)
                
                if parsed.path and parsed.path != '/':
                    paths['deep'] += 1
                else:
                    paths['root'] += 1
                    
            except:
                continue
        
        # Calculate metrics
        unique_domains = len(set(domains))
        unique_tlds = len(set(tlds))
        https_ratio = protocols['https'] / max(1, sum(protocols.values()))
        
        return {
            'success': True,
            'total_urls': len(urls),
            'unique_domains': unique_domains,
            'unique_tlds': unique_tlds,
            'top_tlds': [tld for tld, _ in Counter(tlds).most_common(10)],
            'https_ratio': https_ratio,
            'protocol_distribution': protocols,
            'path_distribution': paths,
            'sample_urls': urls[:5],
            'data_type': 'Live phishing threats',
            'timeliness': 'Real-time feed (updated frequently)'
        }
    
    def analyze_tranco(self):
        """Analyze Tranco domain rankings"""
        print("🔍 Analyzing Tranco data...")
        
        filepath = 'real_data/tranco_domains.csv'
        if not os.path.exists(filepath):
            return {'success': False, 'error': 'Tranco data not found'}
        
        domains = []
        tlds = []
        
        with open(filepath, 'r') as f:
            for line in f:
                if ',' in line:
                    try:
                        rank, domain = line.strip().split(',', 1)
                        domains.append(domain)
                        
                        if '.' in domain:
                            tld = domain.split('.')[-1]
                            tlds.append(tld)
                    except:
                        continue
        
        # Calculate metrics
        domain_lengths = [len(domain) for domain in domains]
        avg_length = sum(domain_lengths) / len(domain_lengths) if domain_lengths else 0
        
        return {
            'success': True,
            'total_domains': len(domains),
            'unique_tlds': len(set(tlds)),
            'top_tlds': [tld for tld, _ in Counter(tlds).most_common(10)],
            'avg_domain_length': avg_length,
            'top_domains': domains[:10],
            'data_type': 'Popular legitimate domains',
            'timeliness': 'Daily updates',
            'ranking_methodology': 'Research-grade aggregation'
        }
    
    def analyze_urlhaus(self):
        """Analyze URLhaus data if available"""
        print("🔍 Analyzing URLhaus data...")
        
        filepath = 'real_data/urlhaus_data.csv'
        if not os.path.exists(filepath):
            return {'success': False, 'error': 'URLhaus data not found'}
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        lines = content.count('\n')
        
        return {
            'success': True,
            'total_records': lines,
            'data_type': 'Malware URLs',
            'content_sample': content[:200],
            'timeliness': 'Frequent updates'
        }
    
    def compare_datasets(self):
        """Compare characteristics across datasets"""
        print("📊 Comparing datasets...")
        
        comparison = {
            'accessibility': {},
            'data_volume': {},
            'timeliness': {},
            'use_cases': {}
        }
        
        # Accessibility
        if self.results.get('openphish', {}).get('success'):
            comparison['accessibility']['openphish'] = 'Immediately accessible'
            comparison['data_volume']['openphish'] = self.results['openphish']['total_urls']
            comparison['timeliness']['openphish'] = 'Real-time'
            comparison['use_cases']['openphish'] = 'Threat detection, ML training'
        
        if self.results.get('tranco', {}).get('success'):
            comparison['accessibility']['tranco'] = 'Immediately accessible' 
            comparison['data_volume']['tranco'] = self.results['tranco']['total_domains']
            comparison['timeliness']['tranco'] = 'Daily'
            comparison['use_cases']['tranco'] = 'Benign baseline, reproducible research'
        
        if self.results.get('urlhaus', {}).get('success'):
            comparison['accessibility']['urlhaus'] = 'Sometimes accessible'
            comparison['data_volume']['urlhaus'] = self.results['urlhaus']['total_records']
            comparison['timeliness']['urlhaus'] = 'Frequent'
            comparison['use_cases']['urlhaus'] = 'Malware research'
        
        return comparison
    
    def generate_recommendations(self):
        """Generate practical recommendations based on analysis"""
        print("💡 Generating recommendations...")
        
        recommendations = {}
        
        # ML Training recommendations
        if (self.results.get('openphish', {}).get('success') and 
            self.results.get('tranco', {}).get('success')):
            
            threat_count = self.results['openphish']['total_urls']
            benign_count = self.results['tranco']['total_domains']
            
            recommendations['ml_training'] = {
                'recommended_approach': 'OpenPhish + Tranco combination',
                'threat_samples': threat_count,
                'benign_samples': benign_count,
                'balance_ratio': f"1:{benign_count//threat_count}" if threat_count > 0 else "Unlimited benign",
                'advantages': ['Both immediately accessible', 'Complementary data types', 'No API keys needed'],
                'considerations': ['May need benign sample balancing', 'Tranco domains need validation']
            }
        
        # Real-time detection
        if self.results.get('openphish', {}).get('success'):
            recommendations['real_time_detection'] = {
                'recommended_dataset': 'OpenPhish',
                'update_frequency': 'Real-time feed',
                'current_volume': self.results['openphish']['total_urls'],
                'advantages': ['Latest threats', 'No delays', 'Free access'],
                'considerations': ['Limited historical data', 'Volume varies']
            }
        
        # Research reproducibility
        if self.results.get('tranco', {}).get('success'):
            recommendations['reproducible_research'] = {
                'recommended_dataset': 'Tranco',
                'methodology': 'Research-grade ranking',
                'volume': self.results['tranco']['total_domains'],
                'advantages': ['Consistent methodology', 'Historical archives', 'Academic focus'],
                'considerations': ['Daily update cycle', 'Legitimate domains only']
            }
        
        return recommendations
    
    def run_analysis(self):
        """Run complete analysis pipeline"""
        print("="*60)
        print("REAL CYBERSECURITY DATA ANALYSIS")
        print("="*60)
        
        # Analyze each dataset
        self.results['openphish'] = self.analyze_openphish()
        self.results['tranco'] = self.analyze_tranco()
        self.results['urlhaus'] = self.analyze_urlhaus()
        
        # Generate comparisons and recommendations
        comparison = self.compare_datasets()
        recommendations = self.generate_recommendations()
        
        # Compile final results
        final_results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'dataset_analysis': self.results,
            'dataset_comparison': comparison,
            'practical_recommendations': recommendations,
            'methodology': 'Real data analysis - no estimates or simulations'
        }
        
        # Save results
        os.makedirs('real_analysis_outputs', exist_ok=True)
        with open('real_analysis_outputs/analysis_results.json', 'w') as f:
            json.dump(final_results, f, indent=2)
        
        # Print summary
        self.print_summary(final_results)
        
        return final_results
    
    def print_summary(self, results):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        
        successful = 0
        total_records = 0
        
        for dataset, analysis in results['dataset_analysis'].items():
            if analysis.get('success'):
                successful += 1
                print(f"✅ {dataset.upper()}:")
                
                if dataset == 'openphish':
                    print(f"   • {analysis['total_urls']:,} phishing URLs")
                    print(f"   • {analysis['unique_domains']:,} unique threat domains")
                    print(f"   • {analysis['https_ratio']:.1%} use HTTPS")
                    total_records += analysis['total_urls']
                
                elif dataset == 'tranco':
                    print(f"   • {analysis['total_domains']:,} ranked domains")
                    print(f"   • {analysis['unique_tlds']} different TLDs")
                    print(f"   • Avg domain length: {analysis['avg_domain_length']:.1f} chars")
                    total_records += analysis['total_domains']
                
                elif dataset == 'urlhaus':
                    print(f"   • {analysis['total_records']:,} malware records")
                    total_records += analysis['total_records']
            else:
                print(f"❌ {dataset.upper()}: {analysis.get('error', 'Failed')}")
        
        print(f"\n📊 TOTALS:")
        print(f"   • Successfully analyzed: {successful}/3 datasets")
        print(f"   • Total data records: {total_records:,}")
        print(f"   • Analysis saved to: real_analysis_outputs/analysis_results.json")
        
        if successful > 0:
            print(f"\n🎉 Ready for ML training! Run: python real_phishing_detector.py")

def main():
    """Run the real data analysis"""
    analyzer = RealDataAnalyzer()
    results = analyzer.run_analysis()
    return results

if __name__ == "__main__":
    main()
