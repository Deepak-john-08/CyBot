#!/usr/bin/env python
"""
Test script to check if your ML models can be loaded properly
"""
import os
import sys

def test_tensorflow():
    """Test TensorFlow installation"""
    print("🔍 Testing TensorFlow installation...")
    try:
        import tensorflow as tf
        print(f"✅ TensorFlow installed successfully! Version: {tf.__version__}")
        return True
    except ImportError as e:
        print(f"❌ TensorFlow not installed: {e}")
        print("💡 Install with: pip install tensorflow")
        return False
    except Exception as e:
        print(f"❌ TensorFlow error: {e}")
        return False

def test_joblib():
    """Test joblib installation"""
    print("\n🔍 Testing joblib installation...")
    try:
        import joblib
        print(f"✅ joblib installed successfully!")
        return True
    except ImportError as e:
        print(f"❌ joblib not installed: {e}")
        print("💡 Install with: pip install joblib")
        return False

def test_model_files():
    """Test if model files exist and can be loaded"""
    print("\n🔍 Testing model files...")
    
    # Check TensorFlow model
    tf_model_path = os.path.join('nlp_app', 'models', 'tf_model.h5')
    print(f"TensorFlow model path: {tf_model_path}")
    print(f"TensorFlow model exists: {os.path.exists(tf_model_path)}")
    
    if os.path.exists(tf_model_path):
        try:
            import tensorflow as tf
            print("🔄 Loading TensorFlow model...")
            model = tf.keras.models.load_model(tf_model_path)
            print(f"✅ TensorFlow model loaded! Input shape: {model.input_shape}")
            print(f"✅ Model summary:")
            model.summary()
        except Exception as e:
            print(f"❌ Failed to load TensorFlow model: {e}")
            import traceback
            traceback.print_exc()
    
    # Check TF-IDF vectorizer
    vectorizer_path = os.path.join('nlp_app', 'models', 'tfidf_vectorizer.pkl')
    print(f"\nVectorizer path: {vectorizer_path}")
    print(f"Vectorizer exists: {os.path.exists(vectorizer_path)}")
    
    if os.path.exists(vectorizer_path):
        try:
            import joblib
            print("🔄 Loading TF-IDF vectorizer...")
            vectorizer = joblib.load(vectorizer_path)
            print(f"✅ TF-IDF vectorizer loaded!")
            print(f"✅ Vectorizer type: {type(vectorizer)}")
            
            # Test vectorization
            test_text = ["This is a test email"]
            test_vector = vectorizer.transform(test_text)
            print(f"✅ Test vectorization successful! Shape: {test_vector.shape}")
            
        except Exception as e:
            print(f"❌ Failed to load vectorizer: {e}")
            import traceback
            traceback.print_exc()

def test_prediction():
    """Test full prediction pipeline"""
    print("\n🔍 Testing full prediction pipeline...")
    
    try:
        # Load models
        import tensorflow as tf
        import joblib
        
        tf_model_path = os.path.join('nlp_app', 'models', 'tf_model.h5')
        vectorizer_path = os.path.join('nlp_app', 'models', 'tfidf_vectorizer.pkl')
        
        if not os.path.exists(tf_model_path) or not os.path.exists(vectorizer_path):
            print("❌ Model files not found")
            return
        
        print("🔄 Loading models for prediction test...")
        model = tf.keras.models.load_model(tf_model_path)
        vectorizer = joblib.load(vectorizer_path)
        
        # Test with sample data
        test_texts = [
            "Dear customer, your account has been suspended. Click here to verify.",
            "Hi, let's meet for coffee tomorrow at 3 PM.",
            "URGENT: Update your payment information immediately!"
        ]
        
        for i, text in enumerate(test_texts):
            print(f"\n🧪 Test {i+1}: {text[:50]}...")
            
            # Vectorize
            text_vector = vectorizer.transform([text])
            text_dense = text_vector.toarray()
            
            # Predict
            prediction_prob = model.predict(text_dense, verbose=0)[0][0]
            is_phishing = prediction_prob > 0.5
            
            print(f"📊 Result: {'🚨 PHISHING' if is_phishing else '✅ SAFE'} (Confidence: {prediction_prob:.3f})")
        
        print("\n✅ Full prediction pipeline test successful!")
        
    except Exception as e:
        print(f"❌ Prediction test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("🤖 CyBot ML Models Test Script")
    print("=" * 50)
    
    # Run all tests
    tf_ok = test_tensorflow()
    joblib_ok = test_joblib()
    
    if tf_ok and joblib_ok:
        test_model_files()
        test_prediction()
    else:
        print("\n❌ Prerequisites not met. Please install missing packages.")
    
    print("\n" + "=" * 50)
    print("🏁 Test completed!")