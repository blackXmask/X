#!/usr/bin/env python3
"""
Web Attack Detection - Prediction
Single model for all attack types
"""

import argparse
import pickle
import pandas as pd
import numpy as np
from config.features import FEATURES
from config.labels import LABELS, LABEL_MAPPING

class WebAttackDetector:
    def __init__(self, model_path='models/web_attack_model.pkl'):
        """Load trained model"""
        print(f"Loading model from {model_path}...")
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        print("Model loaded!")
        
        # Reverse mapping for predictions
        self.id_to_label = {v: k for k, v in LABEL_MAPPING.items()}
    
    def predict_single(self, features_dict):
        """
        Predict single sample
        
        Args:
            features_dict: Dictionary with feature names and values
        
        Returns:
            prediction: Predicted attack type
            confidence: Confidence score
            all_probs: Probabilities for all classes
        """
        # Convert to DataFrame
        X = pd.DataFrame([features_dict])
        X = X[FEATURES]  # Ensure correct order
        
        # Predict
        pred_id = self.model.predict(X)[0]
        probs = self.model.predict_proba(X)[0]
        
        prediction = self.id_to_label[pred_id]
        confidence = probs[pred_id]
        
        all_probs = {self.id_to_label[i]: probs[i] for i in range(len(LABELS))}
        
        return prediction, confidence, all_probs
    
    def predict_batch(self, csv_path):
        """Predict batch from CSV"""
        df = pd.read_csv(csv_path)
        X = df[FEATURES]
        
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        results = []
        for i, (pred_id, probs) in enumerate(zip(predictions, probabilities)):
            result = {
                'sample_id': i,
                'predicted_label': self.id_to_label[pred_id],
                'confidence': probs[pred_id],
                'is_attack': pred_id != LABEL_MAPPING['normal']
            }
            # Add all probabilities
            for j, label in enumerate(LABELS):
                result[f'prob_{label}'] = probs[j]
            
            results.append(result)
        
        return pd.DataFrame(results)
    
    def explain_prediction(self, features_dict, top_n=5):
        """Explain which features contributed most"""
        # This is a simplified explanation based on feature values
        # For SHAP values, use shap library
        
        suspicious_features = []
        
        # Rule-based explanation
        if features_dict.get('sql_keyword_count', 0) > 0:
            suspicious_features.append(f"SQL keywords detected: {features_dict['sql_keyword_count']}")
        if features_dict.get('xss_keyword_count', 0) > 0:
            suspicious_features.append(f"XSS patterns detected: {features_dict['xss_keyword_count']}")
        if features_dict.get('path_traversal_sequence_count', 0) > 0:
            suspicious_features.append(f"Path traversal detected: {features_dict['path_traversal_sequence_count']}")
        if features_dict.get('ssrf_indicator_count', 0) > 0:
            suspicious_features.append(f"SSRF patterns detected: {features_dict['ssrf_indicator_count']}")
        if features_dict.get('request_anomaly_score', 0) > 0.5:
            suspicious_features.append(f"High anomaly score: {features_dict['request_anomaly_score']:.2f}")
        
        return suspicious_features

def interactive_demo():
    """Interactive prediction demo"""
    print("\n" + "="*60)
    print("Web Attack Detection - Interactive Demo")
    print("="*60)
    
    detector = WebAttackDetector()
    
    # Example: SQL injection features
    print("\nExample 1: SQL Injection")
    sql_sample = {
        'url_length': 45,
        'path_length': 10,
        'query_string_length': 25,
        'payload_length': 20,
        'special_char_count': 8,
        'digit_count': 2,
        'uppercase_count': 5,
        'lowercase_count': 15,
        'dot_count': 1,
        'slash_count': 3,
        'percent_encoding_count': 0,
        'null_byte_count': 0,
        'path_depth': 2,
        'query_param_count': 1,
        'has_ip_in_url': 0,
        'is_https': 0,
        'payload_entropy': 3.5,
        'special_char_ratio': 0.2,
        'digit_ratio': 0.05,
        'sql_keyword_count': 3,
        'sql_comment_sequence_count': 1,
        'sql_boolean_logic_count': 1,
        'nosql_operator_count': 0,
        'command_injection_count': 0,
        'xss_keyword_count': 0,
        'xss_event_handler_count': 0,
        'xss_context_break_count': 2,
        'path_traversal_sequence_count': 0,
        'path_traversal_depth': 0,
        'lfi_wrapper_usage': 0,
        'ssrf_indicator_count': 0,
        'open_redirect_param_count': 0,
        'has_user_agent': 1,
        'user_agent_length': 50,
        'user_agent_known_bot': 0,
        'header_order_anomaly': 0,
        'has_cookie': 0,
        'cookie_count': 0,
        'has_referer': 1,
        'has_origin': 0,
        'has_authorization': 0,
        'has_content_security_policy': 0,
        'has_strict_transport_security': 0,
        'has_x_frame_options': 1,
        'status_code': 500,
        'response_length': 1500,
        'response_time': 2.5,
        'contains_error': 1,
        'is_redirect': 0,
        'response_entropy': 4.0,
        'secure_cookie_present': 0,
        'httponly_cookie_present': 0,
        'server_header_present': 1,
        'missing_security_headers_count': 3,
        'request_anomaly_score': 0.7
    }
    
    pred, conf, probs = detector.predict_single(sql_sample)
    print(f"Prediction: {pred}")
    print(f"Confidence: {conf:.4f}")
    print("All probabilities:")
    for label, prob in sorted(probs.items(), key=lambda x: -x[1]):
        print(f"  {label}: {prob:.4f}")
    
    explanations = detector.explain_prediction(sql_sample)
    print(f"\nWhy this prediction?")
    for exp in explanations:
        print(f"  - {exp}")
    
    # Example: Normal traffic
    print("\n" + "-"*60)
    print("Example 2: Normal Traffic")
    normal_sample = {k: 0 for k in FEATURES}
    normal_sample.update({
        'url_length': 25,
        'path_length': 5,
        'query_string_length': 0,
        'payload_length': 0,
        'special_char_count': 2,
        'digit_count': 0,
        'uppercase_count': 0,
        'lowercase_count': 20,
        'dot_count': 2,
        'slash_count': 2,
        'percent_encoding_count': 0,
        'null_byte_count': 0,
        'path_depth': 1,
        'query_param_count': 0,
        'has_ip_in_url': 0,
        'is_https': 1,
        'payload_entropy': 0,
        'special_char_ratio': 0.08,
        'digit_ratio': 0,
        'has_user_agent': 1,
        'user_agent_length': 60,
        'user_agent_known_bot': 0,
        'header_order_anomaly': 0,
        'has_cookie': 1,
        'cookie_count': 2,
        'has_referer': 1,
        'has_origin': 0,
        'has_authorization': 0,
        'has_content_security_policy': 1,
        'has_strict_transport_security': 1,
        'has_x_frame_options': 1,
        'status_code': 200,
        'response_length': 5000,
        'response_time': 0.3,
        'contains_error': 0,
        'is_redirect': 0,
        'response_entropy': 5.0,
        'secure_cookie_present': 1,
        'httponly_cookie_present': 1,
        'server_header_present': 1,
        'missing_security_headers_count': 1,
        'request_anomaly_score': 0.1
    })
    
    pred, conf, probs = detector.predict_single(normal_sample)
    print(f"Prediction: {pred}")
    print(f"Confidence: {conf:.4f}")

def main():
    parser = argparse.ArgumentParser(description='Predict web attacks')
    parser.add_argument('--model', '-m', default='models/web_attack_model.pkl',
                       help='Path to trained model')
    parser.add_argument('--input', '-i', help='Input CSV for batch prediction')
    parser.add_argument('--output', '-o', help='Output CSV path')
    parser.add_argument('--demo', action='store_true', help='Run interactive demo')
    
    args = parser.parse_args()
    
    if args.demo:
        interactive_demo()
        return
    
    if args.input:
        # Batch prediction
        detector = WebAttackDetector(args.model)
        results = detector.predict_batch(args.input)
        
        if args.output:
            results.to_csv(args.output, index=False)
            print(f"Results saved to {args.output}")
        
        print(f"\nPredictions summary:")
        print(results['predicted_label'].value_counts())
    else:
        interactive_demo()

if __name__ == '__main__':
    main()