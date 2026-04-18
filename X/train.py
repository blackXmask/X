#!/usr/bin/env python3
"""
Web Attack Detection - XGBoost Multi-Class Training
Single model for all attack types
"""

import argparse
import pickle
import os
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

from config.features import FEATURES
from config.labels import LABELS, LABEL_MAPPING

def load_data(csv_path='data/raw/web_attack_dataset.csv'):
    """Load and prepare dataset"""
    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"Total samples: {len(df)}")
    return df

def train_model(df, output_dir='models'):
    """Train single XGBoost multi-class model"""
    
    # Prepare features and labels
    X = df[FEATURES]
    y = df['label']
    
    print(f"\nFeatures: {len(FEATURES)}")
    print(f"Classes: {len(LABELS)}")
    
    # Show class distribution
    print("\nClass distribution:")
    for label_name, label_id in LABEL_MAPPING.items():
        count = sum(y == label_id)
        print(f"  {label_name} ({label_id}): {count}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTrain size: {len(X_train)}")
    print(f"Test size: {len(X_test)}")
    
    # Calculate class weights for imbalance
    from sklearn.utils.class_weight import compute_class_weight
    classes = np.unique(y_train)
    weights = compute_class_weight('balanced', classes=classes, y=y_train)
    class_weight_dict = {c: w for c, w in zip(classes, weights)}
    print(f"\nClass weights: {class_weight_dict}")
    
    # Train XGBoost
    print("\nTraining XGBoost classifier...")
    model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=len(LABELS),
        eval_metric='mlogloss',
        max_depth=8,
        learning_rate=0.1,
        n_estimators=300,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=1
    )
    
    # Fit with early stopping
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )
    
    # Evaluate
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=LABELS))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=LABELS, yticklabels=LABELS)
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    
    os.makedirs(output_dir, exist_ok=True)
    cm_path = os.path.join(output_dir, 'confusion_matrix.png')
    plt.savefig(cm_path)
    print(f"\nConfusion matrix saved: {cm_path}")
    
    # Feature importance
    importance = pd.DataFrame({
        'feature': FEATURES,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 15 Important Features:")
    print(importance.head(15).to_string(index=False))
    
    # Plot feature importance
    plt.figure(figsize=(10, 8))
    xgb.plot_importance(model, max_num_features=15, importance_type='gain')
    plt.title('Feature Importance (Top 15)')
    plt.tight_layout()
    fi_path = os.path.join(output_dir, 'feature_importance.png')
    plt.savefig(fi_path)
    print(f"Feature importance saved: {fi_path}")
    
    return model, importance

def save_model(model, output_dir='models'):
    """Save model and metadata"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(output_dir, 'web_attack_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    # Save XGBoost native format (better for deployment)
    model_path_xgb = os.path.join(output_dir, 'web_attack_model.json')
    model.save_model(model_path_xgb)
    
    print(f"\n{'='*60}")
    print("MODEL SAVED")
    print(f"{'='*60}")
    print(f"Pickle: {model_path}")
    print(f"JSON:   {model_path_xgb}")
    
    return model_path

def main():
    parser = argparse.ArgumentParser(description='Train web attack detection model')
    parser.add_argument('--data', '-d', default='data/raw/web_attack_dataset.csv',
                       help='Path to CSV dataset')
    parser.add_argument('--output', '-o', default='models',
                       help='Output directory')
    
    args = parser.parse_args()
    
    # Load data
    df = load_data(args.data)
    
    # Train
    model, importance = train_model(df, args.output)
    
    # Save
    save_model(model, args.output)
    
    print(f"\n{'='*60}")
    print("TRAINING COMPLETE")
    print(f"{'='*60}")
    print(f"Model location: {args.output}/")
    print(f"Ready for prediction!")

if __name__ == '__main__':
    main()