#!/usr/bin/env python3
"""
Real Phishing Detector - ML model trained on real cybersecurity datasets
Uses actual OpenPhish and Tranco data for training
"""

import os
import json
from datetime import datetime
from urllib.parse import urlparse
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

class RealPhishingDetector:
    """ML detector trained on real phishing and benign URLs"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 5),
            max_features=10000,
            lowercase=True
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        self.model_trained = False
    
    def extract_url_features(self, url):
        """Extract features from URL string"""
        try:
            parsed = urlparse(url)
            
            features = {
                'url_length': len(url),
                'domain_length': len(parsed.netloc),
                'path_length': len(parsed.path),
                'query_length': len(parsed.query),
                'subdomain_count': parsed.netloc.count('.') - 1,
                'dash_count': url.count('-'),
                'dot_count': url.count('.'),
                'slash_count': url.count('/'),
                'digit_count': sum(c.isdigit() for c in url),
                'has_ip': any(part.isdigit() for part in parsed.netloc.split('.')),
                'is_https': 1 if parsed.scheme == 'https' else 0,
                'suspicious_tlds': 1 if any(tld in parsed.netloc.lower() 
                                          for tld in ['tk', 'ml', 'ga', 'cf']) else 0
            }
            
            return list(features.values())
            
        except:
            return [0] * 12  # Return zeros if parsing fails
    
    def load_real_data(self):
        """Load real phishing and benign data"""
        print("📂 Loading real training data...")
        
        phishing_urls = []
        benign_urls = []
        
        # Load OpenPhish data (phishing)
        openphish_path = 'real_data/openphish_urls.txt'
        if os.path.exists(openphish_path):
            with open(openphish_path, 'r') as f:
                phishing_urls = [line.strip() for line in f if line.strip()]
            print(f"   ✅ Loaded {len(phishing_urls)} phishing URLs from OpenPhish")
        
        # Load Tranco data (benign) - sample it to balance classes
        tranco_path = 'real_data/tranco_domains.csv'
        if os.path.exists(tranco_path):
            with open(tranco_path, 'r') as f:
                domains = []
                for line in f:
                    if ',' in line:
                        try:
                            rank, domain = line.strip().split(',', 1)
                            # Convert domain to full URL for consistency
                            if not domain.startswith('http'):
                                domain = f'https://{domain}'
                            domains.append(domain)
                        except:
                            continue
                
                # Sample benign URLs to balance dataset (2:1 ratio)
                sample_size = min(len(domains), len(phishing_urls) * 2)
                benign_urls = domains[:sample_size]
                
            print(f"   ✅ Loaded {len(benign_urls)} benign URLs from Tranco")
        
        if not phishing_urls or not benign_urls:
            raise ValueError("Could not load training data. Run download_real_datasets.py first.")
        
        return phishing_urls, benign_urls
    
    def train_model(self):
        """Train ML model on real data"""
        print("="*60)
        print("REAL PHISHING DETECTOR TRAINING")
        print("="*60)
        
        # Load data
        phishing_urls, benign_urls = self.load_real_data()
        
        # Prepare training data
        all_urls = phishing_urls + benign_urls
        labels = [1] * len(phishing_urls) + [0] * len(benign_urls)  # 1=phishing, 0=benign
        
        print(f"📊 Training data prepared:")
        print(f"   • Phishing samples: {len(phishing_urls):,}")
        print(f"   • Benign samples: {len(benign_urls):,}")
        print(f"   • Total samples: {len(all_urls):,}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            all_urls, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Vectorize URLs
        print("🔤 Vectorizing URLs...")
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)
        
        # Train classifier
        print("🤖 Training Random Forest classifier...")
        self.classifier.fit(X_train_vec, y_train)
        
        # Make predictions
        y_pred = self.classifier.predict(X_test_vec)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n📈 MODEL PERFORMANCE:")
        print(f"   • Accuracy: {accuracy:.1%}")
        print(f"   • Training samples: {len(X_train):,}")
        print(f"   • Test samples: {len(X_test):,}")
        
        # Detailed classification report
        print(f"\n📋 Detailed Performance:")
        report = classification_report(y_test, y_pred, 
                                     target_names=['Benign', 'Phishing'],
                                     output_dict=True)
        
        for class_name, metrics in report.items():
            if isinstance(metrics, dict):
                precision = metrics.get('precision', 0)
                recall = metrics.get('recall', 0)
                f1 = metrics.get('f1-score', 0)
                print(f"   • {class_name}: Precision={precision:.1%}, Recall={recall:.1%}, F1={f1:.1%}")
        
        # Save model
        self.save_model()
        
        # Create visualizations
        self.create_performance_visualizations(y_test, y_pred, accuracy)
        
        # Test on sample URLs
        self.test_sample_urls()
        
        self.model_trained = True
        
        return {
            'accuracy': accuracy,
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'phishing_samples': len(phishing_urls),
            'benign_samples': len(benign_urls),
            'classification_report': report
        }
    
    def save_model(self):
        """Save trained model and vectorizer"""
        os.makedirs('real_model', exist_ok=True)
        
        joblib.dump(self.classifier, 'real_model/phishing_classifier.pkl')
        joblib.dump(self.vectorizer, 'real_model/url_vectorizer.pkl')
        
        # Save model metadata
        metadata = {
            'trained_timestamp': datetime.now().isoformat(),
            'model_type': 'Random Forest',
            'vectorizer_type': 'TF-IDF Character N-grams',
            'training_data': 'OpenPhish + Tranco',
            'features': 'URL string analysis'
        }
        
        with open('real_model/model_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"💾 Model saved to real_model/")
    
    def load_model(self):
        """Load saved model"""
        try:
            self.classifier = joblib.load('real_model/phishing_classifier.pkl')
            self.vectorizer = joblib.load('real_model/url_vectorizer.pkl')
            self.model_trained = True
            return True
        except:
            return False
    
    def predict(self, url):
        """Predict if URL is phishing"""
        if not self.model_trained:
            if not self.load_model():
                raise ValueError("Model not trained. Run train_model() first.")
        
        url_vec = self.vectorizer.transform([url])
        prediction = self.classifier.predict(url_vec)[0]
        probability = self.classifier.predict_proba(url_vec)[0]
        
        return {
            'url': url,
            'is_phishing': bool(prediction),
            'phishing_probability': probability[1],
            'benign_probability': probability[0]
        }
    
    def test_sample_urls(self):
        """Test model on sample URLs"""
        print(f"\n🧪 Testing on sample URLs:")
        
        # Test URLs (mix of suspicious and legitimate)
        test_urls = [
            'https://google.com',
            'https://github.com',
            'http://suspicious-bank-login.tk/verify.php',
            'https://facebook.com',
            'http://paypal-security-update.ml/login',
            'https://amazon.com',
            'https://microsoft.com'
        ]
        
        for url in test_urls:
            result = self.predict(url)
            status = "🚨 PHISHING" if result['is_phishing'] else "✅ BENIGN"
            confidence = result['phishing_probability']
            print(f"   {status} ({confidence:.1%}): {url}")
    
    def create_performance_visualizations(self, y_test, y_pred, accuracy):
        """Create performance visualization"""
        os.makedirs('real_analysis_outputs', exist_ok=True)
        
        # Confusion Matrix
        plt.figure(figsize=(10, 4))
        
        plt.subplot(1, 2, 1)
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Benign', 'Phishing'],
                   yticklabels=['Benign', 'Phishing'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        # Accuracy Bar Chart
        plt.subplot(1, 2, 2)
        categories = ['Overall\nAccuracy', 'Benign\nRecall', 'Phishing\nRecall']
        
        # Calculate individual class recalls
        tn, fp, fn, tp = cm.ravel()
        benign_recall = tn / (tn + fp) if (tn + fp) > 0 else 0
        phishing_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        scores = [accuracy, benign_recall, phishing_recall]
        colors = ['skyblue', 'lightgreen', 'salmon']
        
        bars = plt.bar(categories, scores, color=colors)
        plt.ylim(0, 1.0)
        plt.ylabel('Score')
        plt.title('Model Performance Metrics')
        
        # Add value labels on bars
        for bar, score in zip(bars, scores):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                    f'{score:.1%}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('real_analysis_outputs/model_performance.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📊 Performance visualization saved to real_analysis_outputs/model_performance.png")

def main():
    """Train phishing detector on real data"""
    detector = RealPhishingDetector()
    
    try:
        results = detector.train_model()
        
        print(f"\n🎉 SUCCESS! Real phishing detector trained with {results['accuracy']:.1%} accuracy")
        print(f"Model ready for deployment and paper inclusion.")
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        print(f"Make sure you've run: python download_real_datasets.py")
        print(f"And: python analyze_real_data.py")

if __name__ == "__main__":
    main()
