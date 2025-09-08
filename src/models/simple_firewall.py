import torch
import torch.nn as nn
import torch.nn.functional as F
import logging
import numpy as np
from typing import Dict, Optional, Tuple, Union
import time

logger = logging.getLogger(__name__)

class SimpleFirewall(nn.Module):
    """Enhanced PyTorch neural network model for firewall threat detection"""
    
    def __init__(self, input_size=10, hidden_size=128, output_size=2, dropout_rate=0.1):
        super(SimpleFirewall, self).__init__()
        
        try:
            self.input_size = input_size
            self.hidden_size = hidden_size
            self.output_size = output_size
            self.dropout_rate = dropout_rate
            
            # Enhanced network architecture
            self.feature_extractor = nn.Sequential(
                nn.Linear(input_size, hidden_size),
                nn.BatchNorm1d(hidden_size),
                nn.ReLU(),
                nn.Dropout(dropout_rate),
                
                nn.Linear(hidden_size, hidden_size // 2),
                nn.BatchNorm1d(hidden_size // 2),
                nn.ReLU(),
                nn.Dropout(dropout_rate),
                
                nn.Linear(hidden_size // 2, hidden_size // 4),
                nn.BatchNorm1d(hidden_size // 4),
                nn.ReLU(),
                nn.Dropout(dropout_rate / 2)
            )
            
            # Main classifier
            self.classifier = nn.Linear(hidden_size // 4, output_size)
            
            # Auxiliary classifier for regularization
            self.aux_classifier = nn.Linear(hidden_size // 2, output_size)
            
            # Confidence estimation
            self.confidence_estimator = nn.Sequential(
                nn.Linear(hidden_size // 4, hidden_size // 8),
                nn.ReLU(),
                nn.Linear(hidden_size // 8, 1),
                nn.Sigmoid()
            )
            
            # Uncertainty estimation
            self.uncertainty_estimator = nn.Sequential(
                nn.Linear(hidden_size // 4, hidden_size // 8),
                nn.ReLU(),
                nn.Linear(hidden_size // 8, 1),
                nn.Sigmoid()
            )
            
            # Initialize weights
            self._initialize_weights()
            
            # Model info
            self.creation_time = time.time()
            self.update_count = 0
            
            logger.debug(f"Enhanced SimpleFirewall model initialized: "
                        f"input={input_size}, hidden={hidden_size}, "
                        f"output={output_size}, dropout={dropout_rate}")
            
        except Exception as e:
            logger.error(f"SimpleFirewall model initialization error: {e}")
            raise
    
    def _initialize_weights(self):
        """Initialize model weights with enhanced strategy"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.BatchNorm1d):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)
    
    def forward(self, x, return_features=False):
        """Enhanced forward pass with auxiliary outputs"""
        try:
            if x.dim() == 1:
                x = x.unsqueeze(0)
            
            # Feature extraction
            features = self.feature_extractor(x)
            
            # Main classification
            logits = self.classifier(features)
            
            # Confidence estimation
            confidence = self.confidence_estimator(features)
            
            # Uncertainty estimation
            uncertainty = self.uncertainty_estimator(features)
            
            # Auxiliary classification (from intermediate features)
            aux_features = None
            aux_logits = None
            for i, layer in enumerate(self.feature_extractor):
                if i == 4:  # After second linear layer
                    aux_features = layer(self.feature_extractor[:4](x))
                    aux_logits = self.aux_classifier(aux_features)
                    break
            
            if aux_logits is None:
                aux_logits = logits.clone()
            
            if return_features:
                return logits, features, confidence.squeeze(-1), aux_logits
            else:
                return logits, features, confidence.squeeze(-1), aux_logits
                
        except Exception as e:
            logger.error(f"SimpleFirewall forward pass error: {e}")
            # Return safe defaults
            batch_size = x.size(0) if x.dim() > 1 else 1
            device = x.device if hasattr(x, 'device') else torch.device('cpu')
            
            logits = torch.zeros(batch_size, self.output_size, device=device)
            features = torch.zeros(batch_size, self.hidden_size // 4, device=device)
            confidence = torch.full((batch_size,), 0.5, device=device)
            aux_logits = torch.zeros(batch_size, self.output_size, device=device)
            
            if return_features:
                return logits, features, confidence, aux_logits
            else:
                return logits, features, confidence, aux_logits
    
    def predict_threat(self, features):
        """Enhanced threat prediction with comprehensive analysis"""
        try:
            self.eval()
            
            # Convert to tensor if needed
            if isinstance(features, (list, np.ndarray)):
                features_tensor = torch.FloatTensor(features)
            else:
                features_tensor = features.clone().detach()
            
            if features_tensor.dim() == 1:
                features_tensor = features_tensor.unsqueeze(0)
            
            with torch.no_grad():
                logits, extracted_features, confidence, aux_logits = self.forward(features_tensor)
                
                # Get probabilities
                probabilities = F.softmax(logits, dim=1)
                aux_probabilities = F.softmax(aux_logits, dim=1)
                
                # Main prediction
                prediction = torch.argmax(logits, dim=1).item()
                threat_probability = probabilities[0, 1].item()  # Probability of threat class
                model_confidence = confidence[0].item()
                
                # Uncertainty estimation (entropy-based)
                entropy = -torch.sum(probabilities * torch.log(probabilities + 1e-8), dim=1)
                normalized_entropy = entropy / np.log(self.output_size)  # Normalize to [0,1]
                uncertainty = normalized_entropy[0].item()
                
                # Auxiliary prediction consistency
                aux_prediction = torch.argmax(aux_logits, dim=1).item()
                prediction_consistency = 1.0 if prediction == aux_prediction else 0.5
                
                # Enhanced confidence calculation
                final_confidence = (
                    0.5 * model_confidence +
                    0.3 * prediction_consistency +
                    0.2 * (1.0 - uncertainty)
                )
                
                return {
                    'prediction': prediction,
                    'is_threat': prediction == 1,
                    'threat_probability': threat_probability,
                    'confidence': final_confidence,
                    'uncertainty': uncertainty,
                    'raw_logits': logits[0].tolist(),
                    'probabilities': probabilities[0].tolist(),
                    'aux_prediction': aux_prediction,
                    'prediction_consistency': prediction_consistency,
                    'entropy': entropy[0].item()
                }
                
        except Exception as e:
            logger.error(f"Threat prediction error: {e}")
            # Return safe defaults
            return {
                'prediction': 0,
                'is_threat': False,
                'threat_probability': 0.5,
                'confidence': 0.5,
                'uncertainty': 0.5,
                'raw_logits': [0.0, 0.0],
                'probabilities': [0.5, 0.5],
                'aux_prediction': 0,
                'prediction_consistency': 0.5,
                'entropy': np.log(2),
                'error': str(e)
            }
    
    def compute_loss(self, logits, labels, aux_logits=None, confidence=None, label_smoothing=0.1):
        """Enhanced loss computation with auxiliary losses"""
        try:
            # Main classification loss with label smoothing
            main_loss = F.cross_entropy(logits, labels, label_smoothing=label_smoothing)
            
            total_loss = main_loss
            
            # Auxiliary loss
            if aux_logits is not None:
                aux_loss = F.cross_entropy(aux_logits, labels, label_smoothing=label_smoothing)
                total_loss += 0.3 * aux_loss
            
            # Confidence regularization
            if confidence is not None:
                # Encourage high confidence for correct predictions
                predictions = torch.argmax(logits, dim=1)
                correct_mask = (predictions == labels).float()
                
                # Confidence should be high for correct predictions, moderate for incorrect
                target_confidence = 0.8 * correct_mask + 0.3 * (1 - correct_mask)
                confidence_loss = F.mse_loss(confidence, target_confidence)
                total_loss += 0.1 * confidence_loss
            
            return total_loss
            
        except Exception as e:
            logger.error(f"Loss computation error: {e}")
            return torch.tensor(1.0, requires_grad=True)
    
    def update_dropout_rate(self, new_dropout_rate):
        """Update dropout rate for all dropout layers"""
        try:
            self.dropout_rate = new_dropout_rate
            
            for module in self.modules():
                if isinstance(module, nn.Dropout):
                    module.p = new_dropout_rate
            
            logger.debug(f"Updated dropout rate to {new_dropout_rate}")
            
        except Exception as e:
            logger.error(f"Dropout rate update error: {e}")
    
    def get_weights(self):
        """Get model weights for federated learning"""
        try:
            weights = {}
            for name, param in self.named_parameters():
                weights[name] = param.data.clone()
            
            self.update_count += 1
            return weights
            
        except Exception as e:
            logger.error(f"Weight extraction error: {e}")
            return {}
    
    def set_weights(self, weights):
        """Set model weights from federated learning"""
        try:
            updated_params = 0
            
            with torch.no_grad():
                for name, param in self.named_parameters():
                    if name in weights:
                        if param.shape == weights[name].shape:
                            param.copy_(weights[name])
                            updated_params += 1
                        else:
                            logger.warning(f"Shape mismatch for {name}: "
                                         f"{param.shape} vs {weights[name].shape}")
                    else:
                        logger.warning(f"Missing weight for parameter: {name}")
            
            self.update_count += 1
            logger.debug(f"Updated {updated_params} parameters from federated weights")
            
        except Exception as e:
            logger.error(f"Weight setting error: {e}")
    
    def get_model_info(self):
        """Get comprehensive model information"""
        try:
            total_params = sum(p.numel() for p in self.parameters())
            trainable_params = sum(p.numel() for p in self.parameters() if p.requires_grad)
            
            return {
                'model_type': 'SimpleFirewall',
                'input_size': self.input_size,
                'hidden_size': self.hidden_size,
                'output_size': self.output_size,
                'dropout_rate': self.dropout_rate,
                'total_parameters': total_params,
                'trainable_parameters': trainable_params,
                'creation_time': self.creation_time,
                'update_count': self.update_count,
                'layer_details': {
                    'feature_extractor_layers': len(self.feature_extractor),
                    'has_aux_classifier': True,
                    'has_confidence_estimator': True,
                    'has_uncertainty_estimator': True
                }
            }
            
        except Exception as e:
            logger.error(f"Model info retrieval error: {e}")
            return {
                'model_type': 'SimpleFirewall',
                'error': str(e),
                'input_size': getattr(self, 'input_size', 10),
                'hidden_size': getattr(self, 'hidden_size', 128),
                'output_size': getattr(self, 'output_size', 2)
            }
    
    def save_model(self, filepath):
        """Save model state"""
        try:
            model_state = {
                'state_dict': self.state_dict(),
                'model_config': {
                    'input_size': self.input_size,
                    'hidden_size': self.hidden_size,
                    'output_size': self.output_size,
                    'dropout_rate': self.dropout_rate
                },
                'model_info': self.get_model_info()
            }
            
            torch.save(model_state, filepath)
            logger.info(f"Model saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Model save error: {e}")
            return False
    
    def load_model(self, filepath):
        """Load model state"""
        try:
            model_state = torch.load(filepath, map_location='cpu')
            
            # Load state dict
            self.load_state_dict(model_state['state_dict'])
            
            # Update configuration
            config = model_state['model_config']
            self.input_size = config['input_size']
            self.hidden_size = config['hidden_size']
            self.output_size = config['output_size']
            self.dropout_rate = config['dropout_rate']
            
            logger.info(f"Model loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Model load error: {e}")
            return False
    
    def reset_parameters(self):
        """Reset all model parameters"""
        try:
            self._initialize_weights()
            self.update_count = 0
            logger.info("Model parameters reset")
            
        except Exception as e:
            logger.error(f"Parameter reset error: {e}")