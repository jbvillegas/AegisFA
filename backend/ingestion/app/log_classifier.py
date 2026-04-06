import pickle
from collections import Counter
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder

# Model cache
_rf_model = None
_vectorizer = None # Not used globally at the moment, but kept for potential future use.
_label_encoder = None # Not used globally at the moment, but kept for potential future use.
_model_path = Path(__file__).parent / ".models"


class LogClassifier: #LABELS
    
    # Predefined log categories
    LOG_CATEGORIES = [
        "authentication",
        "authorization", 
        "network",
        "system",
        "application",
        "database",
        "security",
        "performance",
        "error",
        "anomaly"
    ]
    
    def __init__(self):
        self.model = None
        self.vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(self.LOG_CATEGORIES)
        self.is_trained = False
        self.training_metadata = {}

    def _flatten_pairs(self, data: Dict, prefix: str = "") -> List[Tuple[str, str]]:
        """Flatten nested dictionaries/lists into key-value text pairs."""
        pairs: List[Tuple[str, str]] = []
        if not isinstance(data, dict):
            return pairs

        for key, value in data.items():
            normalized_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                pairs.extend(self._flatten_pairs(value, normalized_key))
            elif isinstance(value, list):
                joined = "|".join(str(item).lower() for item in value[:10])
                pairs.append((normalized_key, joined))
            elif isinstance(value, (str, int, float, bool)):
                pairs.append((normalized_key, str(value).lower()))

        return pairs

    def _normalize_label(self, label: str) -> str: ## Map unknown labels into a safe default category
        if label in self.LOG_CATEGORIES:
            return label
        return "Anomaly"

    def _rule_based_guess(self, log_entry: Dict) -> str: ##Fallback heuristic classification based on key terms in the log entry.
        text = self.extract_features(log_entry)
        if any(term in text for term in ("login", "auth", "password", "mfa")):
            return "authentication"
        if any(term in text for term in ("deny", "permission", "forbidden", "access")):
            return "authorization"
        if any(term in text for term in ("sql", "db", "query", "database")):
            return "database"
        if any(term in text for term in ("latency", "timeout", "slow", "cpu", "memory")):
            return "performance"
        if any(term in text for term in ("error", "exception", "failed", "stacktrace")):
            return "error"
        if any(term in text for term in ("ip", "port", "connection", "dns", "firewall")):
            return "network"
        return "anomaly"
    
    def extract_features(self, log_entry: Dict) -> str:
        if not isinstance(log_entry, dict):
            return ""

        features: List[str] = []
        for key, value in self._flatten_pairs(log_entry):
            features.append(f"{key}:{value}")
            if key.split(".")[-1] in {"message", "action", "status", "user", "ip", "event_type", "severity"}: ## Relevant features for classification.
                features.append(value)

        return " ".join(features)
    
    def train(self, training_data: List[Tuple[Dict, str]], test_size: float = 0.2):
        
        if not training_data:
            return {"ERROR": "No training data provided"}
        
        # Extract features and use label space directly from provided training set.
        texts = [self.extract_features(entry) for entry, _ in training_data]
        labels = [str(category).strip().lower() for _, category in training_data if str(category).strip()]

        if len(labels) != len(training_data):
            return {"ERROR": "Training data contains EMPTY labels"}

        if not any(texts):
            return {"ERROR": "Training data produced EMPTY feature set"}

        classes = sorted(set(labels))
        if len(classes) < 2:
            return {"ERROR": "Training requires at least TWO unique classes"}

        self.label_encoder.fit(classes)
        
        # Vectorize text
        X = self.vectorizer.fit_transform(texts).toarray()
        y = self.label_encoder.transform(labels)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X, y)
        self.is_trained = True
        self.training_metadata = {
            "label_distribution": dict(Counter(labels)),
            "n_samples": len(training_data),
            "classes": classes,
        }
        
        # Calculate training accuracy
        train_score = self.model.score(X, y)
        
        return {
            "status": "trained",
            "accuracy": float(train_score),
            "n_samples": len(training_data),
            "categories": classes,
            "label_distribution": dict(Counter(labels)),
        }

    def evaluate(self, labeled_data: List[Tuple[Dict, str]]) -> Dict:
        """Evaluate the trained model on a labeled split."""
        if not self.is_trained or self.model is None:
            return {"ERROR": "Classifier not trained"}

        if not labeled_data:
            return {"ERROR": "No evaluation data provided"}

        entries = [entry for entry, _ in labeled_data]
        y_true = [str(label).strip().lower() for _, label in labeled_data]
        predictions = self.classify_batch(entries)
        y_pred = [prediction.get("category", "") for prediction in predictions]

        accuracy = float(accuracy_score(y_true, y_pred))
        precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
            y_true,
            y_pred,
            average="macro",
            zero_division=0,
        )
        precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0,
        )

        labels = list(self.label_encoder.classes_)
        cm = confusion_matrix(y_true, y_pred, labels=labels)

        return {
            "samples": len(labeled_data),
            "accuracy": accuracy,
            "precision_macro": float(precision_macro),
            "recall_macro": float(recall_macro),
            "f1_macro": float(f1_macro),
            "precision_weighted": float(precision_weighted),
            "recall_weighted": float(recall_weighted),
            "f1_weighted": float(f1_weighted),
            "labels": labels,
            "confusion_matrix": cm.tolist(),
        }
    
    def classify(self, log_entry: Dict, include_mitre: bool = True) -> Dict:
    
        if not self.is_trained or self.model is None:
            guessed = self._rule_based_guess(log_entry)
            return {
                "status": "fallback",
                "category": guessed,
                "confidence": 0.0,
                "top_predictions": [{"category": guessed, "confidence": 0.0}],
                "key_terms": self.extract_features(log_entry).split()[:5],
                "reasoning": "RF model not trained; used heuristic fallback classification."
            }
        
        # Extract and vectorize features
        text = self.extract_features(log_entry)
        X = self.vectorizer.transform([text]).toarray()
        
        # Get prediction and probabilities
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        category = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(np.max(probabilities))
        
        # Get top 3 predictions
        top_indices = np.argsort(probabilities)[-3:][::-1]
        top_predictions = [
            {
                "category": self.label_encoder.inverse_transform([idx])[0],
                "confidence": float(probabilities[idx])
            }
            for idx in top_indices
        ]
        
        # Extract key features for reasoning
        extracted_text = self.extract_features(log_entry)
        key_terms = extracted_text.split()[:5]
        
        result = {
            "category": category,
            "confidence": confidence,
            "top_predictions": top_predictions,
            "key_terms": key_terms,
            "reasoning": f"Classified as '{category}' based on features: {', '.join(key_terms)}"
        }
        
        # Optionally enrich with MITRE mapping
        if include_mitre:
            from .rf_training_mapping import get_mitre_with_confidence
            mitre_data = get_mitre_with_confidence(category, confidence)
            result["mitre_techniques"] = mitre_data.get("techniques", [])
            result["mitre_summary"] = mitre_data.get("summary", "")
            result["mitre_severity"] = mitre_data.get("severity", "medium")
            result["adjusted_severity"] = mitre_data.get("adjusted_severity", "medium")
            result["confidence_score"] = mitre_data.get("confidence_score", confidence)
        
        return result
    
    def classify_batch(self, log_entries: List[Dict], include_mitre: bool = True) -> List[Dict]:
        
        if not log_entries:
            return []

        if not self.is_trained or self.model is None:
            return [self.classify(entry, include_mitre=include_mitre) for entry in log_entries]

        texts = [self.extract_features(entry) for entry in log_entries]
        X = self.vectorizer.transform(texts).toarray()
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)

        results = []
        for i, prediction in enumerate(predictions):
            probs = probabilities[i]
            category = self.label_encoder.inverse_transform([prediction])[0]
            confidence = float(np.max(probs))
            top_indices = np.argsort(probs)[-3:][::-1]
            top_predictions = [
                {
                    "category": self.label_encoder.inverse_transform([idx])[0],
                    "confidence": float(probs[idx]),
                }
                for idx in top_indices
            ]
            key_terms = texts[i].split()[:5]

            result = {
                "status": "classified",
                "category": category,
                "confidence": confidence,
                "top_predictions": top_predictions,
                "key_terms": key_terms,
                "reasoning": f"Classified as '{category}' based on structured feature vector.",
            }
            
            # MITRE MAPPING
            if include_mitre:
                from .rf_training_mapping import get_mitre_with_confidence
                mitre_data = get_mitre_with_confidence(category, confidence)
                result["mitre_techniques"] = mitre_data.get("techniques", [])
                result["mitre_summary"] = mitre_data.get("summary", "")
                result["mitre_severity"] = mitre_data.get("severity", "medium")
                result["adjusted_severity"] = mitre_data.get("adjusted_severity", "medium")
                result["confidence_score"] = mitre_data.get("confidence_score", confidence)

            results.append(result)

        return results
    
    def get_feature_importance(self) -> Dict:
        
        if not self.is_trained or self.model is None:
            return {"ERROR": "Classifier not trained"}
        
        # Get feature names from vectorizer
        feature_names = self.vectorizer.get_feature_names_out()
        importances = self.model.feature_importances_
        
        # Get top 20 important features
        top_indices = np.argsort(importances)[-20:][::-1]
        
        return {
            "top_features": [
                {
                    "feature": feature_names[idx],
                    "importance": float(importances[idx])
                }
                for idx in top_indices
            ]
        }
    
    def save_model(self, filepath: str = None):
       
        if not self.is_trained:
            return {"error": "No trained model to save"}
        
        if filepath is None:
            _model_path.mkdir(exist_ok=True)
            filepath = _model_path / "rf_classifier.pkl"
        
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'vectorizer': self.vectorizer,
                'label_encoder': self.label_encoder,
                'training_metadata': self.training_metadata,
            }, f)
        
        return {"status": "saved", "path": str(filepath)}
    
    def load_model(self, filepath: str = None):
        
        if filepath is None:
            filepath = _model_path / "rf_classifier.pkl"
        
        if not Path(filepath).exists():
            return {"ERROR": f"Model file not found: {filepath}"}
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.vectorizer = data['vectorizer']
            self.label_encoder = data['label_encoder']
            self.training_metadata = data.get('training_metadata', {})
            self.is_trained = True
        
        return {"status": "loaded", "path": str(filepath)}


def get_classifier() -> LogClassifier:

    global _rf_model
    if _rf_model is None:
        _rf_model = LogClassifier()
    return _rf_model
