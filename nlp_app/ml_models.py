import os
import numpy as np
from django.conf import settings

# Global variable to store loaded BERT model
_bert_model = None

def load_models():
    """Load BERT phishing detection model"""
    global _bert_model
    
    models_dir = os.path.join(settings.BASE_DIR, 'nlp_app', 'models')
    bert_model_path = os.path.join(models_dir, 'bert_phishing_model_tf')
    
    if os.path.exists(bert_model_path) and _bert_model is None:
        try:
            import tensorflow as tf
            print("🧠 Loading BERT phishing detection model...")
            _bert_model = tf.saved_model.load(bert_model_path)
            print("✅ BERT phishing model loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading BERT model: {e}")
    elif not os.path.exists(bert_model_path):
        print(f"❌ BERT model not found at: {bert_model_path}")

def lazy_load_models():
    """Load models only when needed"""
    global _bert_model
    if _bert_model is None:
        load_models()

def predict_email_phishing(email_text):
    """Predict if email is phishing using BERT model"""
    # For now, disable BERT model due to tokenization issues
    # Return None to trigger rule-based fallback
    print("🔄 Using rule-based detection (BERT tokenization needs proper tokenizer)")
    return None, 0.0

def predict_url_phishing(url):
    """Predict if URL is phishing using BERT model"""
    # For now, disable BERT model due to tokenization issues
    # Return None to trigger rule-based fallback
    print("🔄 Using rule-based detection (BERT tokenization needs proper tokenizer)")
    return None, 0.0