
import asyncio
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import logging
import time
import json
import threading
from pathlib import Path

# Import with error handling
try:
    from models.simple_firewall import SimpleFirewall
    from core.simple_packet_analyzer import SimplePacketAnalyzer
    from core.firewall_manager import SimpleFirewallManager
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.error(f"Import error in federated client: {e}")
    raise

logger = logging.getLogger(__name__)

class SimpleFederatedClient:
    """ENHANCED federated learning client with superior performance and stability"""
    
    def __init__(self, client_id, config, mininet_host=None):
        try:
            self.client_id = client_id
            self.config = config
            self.mininet_host = mininet_host
            
            # Host information with enhanced error handling
            if mininet_host:
                try:
                    self.host_name = mininet_host.name
                    self.host_ip = mininet_host.IP()
                except Exception as e:
                    logger.error(f"Error getting host info: {e}")
                    self.host_name = f"client_{client_id}"
                    self.host_ip = f"10.0.0.{client_id + 1}"
            else:
                self.host_name = f"client_{client_id}"
                self.host_ip = f"10.0.0.{client_id + 1}"
            
            # Initialize enhanced model
            try:
                model_config = config.get('model', {})
                hyper_config = config.get('hyperparameters', {})
                
                self.model = SimpleFirewall(
                    input_size=model_config.get('input_size', 10),
                    hidden_size=hyper_config.get('hidden_sizes', [128])[0],
                    output_size=model_config.get('output_size', 2),
                    dropout_rate=hyper_config.get('dropout_rates', [0.1])[0]
                )
            except Exception as e:
                logger.error(f"Enhanced model initialization error: {e}")
                self.model = SimpleFirewall(input_size=10, hidden_size=128, output_size=2, dropout_rate=0.1)
            
            # Initialize components
            self.packet_analyzer = SimplePacketAnalyzer()
            self.firewall_manager = SimpleFirewallManager(config)
            
            # Enhanced learning configuration with adaptive parameters
            self.learning_config = self._initialize_learning_config(config)
            self.optimizer = self._create_optimizer()
            self.scheduler = self._create_scheduler()
            
            # Data management with better organization
            self.training_data = []
            self.validation_data = []
            self.test_data = []
            self.max_training_samples = 3000  # Increased capacity
            self.validation_split = 0.15  # Slightly smaller validation set
            
            # Enhanced state management
            self.is_running = False
            self.current_phase = "learning"
            self.phase_lock = asyncio.Lock()
            self.training_round = 0
            self.phase_transition_flag = False
            
            # Enhanced performance tracking
            self.performance_metrics = self._initialize_performance_metrics()
            self.hyperparameter_history = self._initialize_hyperparameter_tracking()
            
            # Task and thread management
            self.running_tasks = []
            self.stats_lock = threading.Lock()
            
            logger.info(f"Enhanced client {self.host_name} initialized with superior architecture")
            
        except Exception as e:
            logger.error(f"Enhanced client initialization error: {e}")
            raise
    
    def _initialize_learning_config(self, config):
        """Initialize enhanced learning configuration"""
        try:
            fed_config = config.get('federated', {})
            hyper_config = config.get('hyperparameters', {})
            
            return {
                'learning_rate': hyper_config.get('learning_rates', [0.005])[0],
                'dropout_rate': hyper_config.get('dropout_rates', [0.1])[0],
                'batch_size': fed_config.get('batch_size', 32),
                'local_epochs': fed_config.get('local_epochs', 4),
                'min_batch_size': fed_config.get('min_batch_size', 8),
                'weight_decay': 1e-5,
                'gradient_clip_norm': 1.0,
                'label_smoothing': 0.1
            }
        except Exception as e:
            logger.error(f"Learning config initialization error: {e}")
            return {
                'learning_rate': 0.005, 'dropout_rate': 0.1, 'batch_size': 32,
                'local_epochs': 4, 'min_batch_size': 8, 'weight_decay': 1e-5,
                'gradient_clip_norm': 1.0, 'label_smoothing': 0.1
            }
    
    def _create_optimizer(self):
        """Create enhanced optimizer with better defaults"""
        try:
            return optim.AdamW(
                self.model.parameters(),
                lr=self.learning_config['learning_rate'],
                weight_decay=self.learning_config['weight_decay'],
                betas=(0.9, 0.999),
                eps=1e-8
            )
        except Exception as e:
            logger.error(f"Optimizer creation error: {e}")
            return optim.Adam(self.model.parameters(), lr=0.005)
    
    def _create_scheduler(self):
        """Create enhanced learning rate scheduler"""
        try:
            return optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer,
                mode='min',
                factor=0.7,  # Less aggressive reduction
                patience=5,  # More patience
                min_lr=1e-5
            )
        except Exception as e:
            logger.error(f"Scheduler creation error: {e}")
            return None
    
    def get_current_learning_rate(self):
        """Get current learning rate using get_last_lr() method"""
        try:
            if self.scheduler and hasattr(self.scheduler, 'get_last_lr'):
                return self.scheduler.get_last_lr()[0] if self.scheduler.get_last_lr() else self.learning_config['learning_rate']
            else:
                return self.learning_config['learning_rate']
        except Exception as e:
            logger.error(f"Error getting current learning rate: {e}")
            return self.learning_config['learning_rate']
    
    def _initialize_performance_metrics(self):
        """Initialize enhanced performance tracking"""
        return {
            'packets_processed': 0,
            'threats_detected': 0,
            'model_accuracy': 0.0,
            'model_loss': 0.0,
            'training_loss_history': [],
            'validation_accuracy_history': [],
            'confidence_scores': [],
            'last_update_time': time.time(),
            'phase_accuracy_history': {'learning': [], 'testing': []},
            'gradient_norms': [],
            'learning_curves': {'train_loss': [], 'val_accuracy': []},
            'threat_detection_rate': 0.0,
            'false_positive_rate': 0.0
        }
    
    def _initialize_hyperparameter_tracking(self):
        """Initialize hyperparameter tracking"""
        return {
            'learning_rates': [self.learning_config['learning_rate']],
            'dropout_rates': [self.learning_config['dropout_rate']],
            'batch_sizes': [self.learning_config['batch_size']],
            'optimization_history': []
        }
    
    async def start(self):
        """Start enhanced federated client operations"""
        if self.is_running:
            logger.warning(f"Enhanced client {self.host_name} already running")
            return
        
        try:
            self.is_running = True
            logger.info(f"Starting enhanced federated client {self.host_name}")
            
            # Generate superior initial training data
            await self._generate_enhanced_initial_data()
            
            # Start all enhanced background tasks
            tasks = [
                self._enhanced_packet_processing_loop(),
                self._enhanced_training_loop(),
                self._enhanced_status_reporting_loop(),
                self._enhanced_data_management_loop(),
                self._performance_optimization_loop(),
                self._adaptive_hyperparameter_loop()
            ]
            
            self.running_tasks = [asyncio.create_task(task) for task in tasks]
            
            # Wait for tasks with enhanced error handling
            results = await asyncio.gather(*self.running_tasks, return_exceptions=True)
            
            # Log any exceptions from tasks
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Task {i} failed: {result}")
            
        except Exception as e:
            logger.error(f"Enhanced client {self.host_name} startup error: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """Enhanced graceful shutdown"""
        if not self.is_running:
            return
        
        try:
            logger.info(f"Stopping enhanced client {self.host_name}")
            self.is_running = False
            
            # Cancel all running tasks with timeout
            for task in self.running_tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for cancellation with timeout
            if self.running_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self.running_tasks, return_exceptions=True),
                        timeout=15.0
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Enhanced client {self.host_name} shutdown timeout")
            
            self.running_tasks.clear()
            logger.info(f"Enhanced client {self.host_name} stopped successfully")
            
        except Exception as e:
            logger.error(f"Enhanced client stop error: {e}")
    
    async def on_phase_change(self, new_phase):
        """Enhanced phase change handling with better synchronization"""
        try:
            async with self.phase_lock:
                old_phase = self.current_phase
                self.phase_transition_flag = True
                
                logger.info(f"{self.host_name}: Enhanced phase transition {old_phase} -> {new_phase}")
                
                # Wait for current operations to complete
                await asyncio.sleep(3)
                
                # Phase-specific preparations
                if new_phase == "testing":
                    await self._prepare_for_testing_phase()
                elif new_phase == "learning":
                    await self._prepare_for_learning_phase()
                
                # Update phase
                self.current_phase = new_phase
                self.phase_transition_flag = False
                
                # Update performance history
                if old_phase in self.performance_metrics['phase_accuracy_history']:
                    current_accuracy = self.performance_metrics['model_accuracy']
                    self.performance_metrics['phase_accuracy_history'][old_phase].append(current_accuracy)
                
                logger.info(f"{self.host_name}: Enhanced phase change to {new_phase} completed")
                
        except Exception as e:
            logger.error(f"Enhanced phase change error for {self.host_name}: {e}")
            self.phase_transition_flag = False
    
    async def _prepare_for_testing_phase(self):
        """Enhanced testing phase preparation"""
        try:
            logger.info(f"{self.host_name}: Preparing for enhanced testing phase...")
            
            # Set model to evaluation mode
            self.model.eval()
            
            # Prepare test dataset from recent data
            if len(self.training_data) > 50:
                self.test_data = self.training_data[-50:].copy()
            
            # Adjust data collection for testing
            self.validation_data = self.training_data[-100:] if len(self.training_data) > 100 else self.training_data.copy()
            
            logger.info(f"{self.host_name}: Enhanced testing phase preparation completed")
            
        except Exception as e:
            logger.error(f"Enhanced testing phase preparation error: {e}")
    
    async def _prepare_for_learning_phase(self):
        """Enhanced learning phase preparation"""
        try:
            logger.info(f"{self.host_name}: Preparing for enhanced learning phase...")
            
            # Set model to training mode
            self.model.train()
            
            # Reset test data
            self.test_data = []
            
            # Prepare validation split
            if len(self.training_data) > 20:
                split_idx = int(len(self.training_data) * (1 - self.validation_split))
                self.validation_data = self.training_data[split_idx:]
            
            logger.info(f"{self.host_name}: Enhanced learning phase preparation completed")
            
        except Exception as e:
            logger.error(f"Enhanced learning phase preparation error: {e}")
    
    async def _enhanced_packet_processing_loop(self):
        """Enhanced packet processing with better threat generation"""
        
        while self.is_running:
            try:
                # Phase-adaptive processing intervals
                if self.current_phase == "learning":
                    packet_interval = 0.3  # Faster during learning
                elif self.current_phase == "testing":
                    packet_interval = 0.2  # Fastest during testing
                else:
                    packet_interval = 0.5
                
                # Skip during phase transitions
                if self.phase_transition_flag:
                    await asyncio.sleep(1)
                    continue
                
                # Extract enhanced features
                features = self.packet_analyzer.extract_features()
                
                # Get enhanced model prediction
                prediction_info = self.model.predict_threat(features)
                
                # Analyze with firewall
                firewall_action = self.firewall_manager.analyze_packet(features, prediction_info)
                
                # Generate enhanced training label
                true_label = self._generate_enhanced_synthetic_label(features, prediction_info)
                
                # Create enhanced training sample
                training_sample = {
                    'features': features.copy(),
                    'label': true_label,
                    'prediction': prediction_info['prediction'],
                    'confidence': prediction_info['confidence'],
                    'uncertainty': prediction_info.get('uncertainty', 0.5),
                    'timestamp': time.time(),
                    'firewall_action': firewall_action['action'],
                    'phase': self.current_phase,
                    'threat_probability': prediction_info.get('threat_probability', 0.5)
                }
                
                # Phase-specific data handling
                with self.stats_lock:
                    if self.current_phase == "learning":
                        self.training_data.append(training_sample)
                    elif self.current_phase == "testing":
                        self.test_data.append(training_sample)
                    
                    # Update performance metrics
                    self.performance_metrics['packets_processed'] += 1
                    if true_label == 1:
                        self.performance_metrics['threats_detected'] += 1
                    
                    # Track confidence scores
                    self.performance_metrics['confidence_scores'].append(prediction_info['confidence'])
                    if len(self.performance_metrics['confidence_scores']) > 100:
                        self.performance_metrics['confidence_scores'] = self.performance_metrics['confidence_scores'][-50:]
                
                # Log significant threats with enhanced information
                if prediction_info.get('is_threat', False) and prediction_info.get('confidence', 0) > 0.7:
                    logger.debug(f"{self.host_name} [{self.current_phase.upper()}]: HIGH THREAT - "
                               f"Confidence: {prediction_info['confidence']:.3f}, "
                               f"Uncertainty: {prediction_info.get('uncertainty', 0):.3f}, "
                               f"Action: {firewall_action['action']}")
                
                await asyncio.sleep(packet_interval)
                
            except Exception as e:
                logger.error(f"Enhanced packet processing error in {self.host_name}: {e}")
                await asyncio.sleep(1)
    
    async def _enhanced_training_loop(self):
        """Enhanced training loop with superior optimization"""
        
        while self.is_running:
            try:
                # Phase-specific training intervals
                if self.current_phase == "learning":
                    training_interval = 12  # More frequent during learning
                elif self.current_phase == "testing":
                    training_interval = 25  # Less frequent during testing
                else:
                    training_interval = 15
                
                # Skip during phase transitions
                if self.phase_transition_flag:
                    await asyncio.sleep(5)
                    continue
                
                min_batch_size = self.learning_config['min_batch_size']
                available_samples = len(self.training_data)
                
                if available_samples >= min_batch_size and self.current_phase == "learning":
                    await self._enhanced_model_training()
                    self.training_round += 1
                    
                    # Periodic detailed logging
                    if self.training_round % 5 == 0:
                        await self._log_training_progress()
                
                elif self.current_phase == "testing" and len(self.test_data) >= min_batch_size:
                    await self._enhanced_model_validation()
                
                await asyncio.sleep(training_interval)
                
            except Exception as e:
                logger.error(f"Enhanced training loop error in {self.host_name}: {e}")
                await asyncio.sleep(5)
    
    async def _enhanced_model_training(self):
        """Superior model training with advanced techniques"""
        try:
            min_batch_size = self.learning_config['min_batch_size']
            if len(self.training_data) < min_batch_size:
                return
            
            # Prepare enhanced balanced dataset
            recent_data = self.training_data[-1000:] if len(self.training_data) > 1000 else self.training_data
            
            # Enhanced class balancing
            threat_samples = [d for d in recent_data if d['label'] == 1]
            normal_samples = [d for d in recent_data if d['label'] == 0]
            
            # Dynamic balancing based on current performance
            threat_ratio = len(threat_samples) / max(len(recent_data), 1)
            if threat_ratio < 0.2:  # Too few threats
                # Oversample threat samples
                threat_samples = threat_samples * 3
            elif threat_ratio > 0.6:  # Too many threats
                # Undersample threat samples
                threat_samples = threat_samples[:len(threat_samples)//2]
            
            # Combine and sample
            all_samples = threat_samples + normal_samples
            if len(all_samples) < min_batch_size:
                return
            
            # Sample with weighted selection favoring recent and uncertain samples
            sample_weights = []
            current_time = time.time()
            for sample in all_samples:
                # Weight by recency
                age_weight = np.exp(-(current_time - sample['timestamp']) / 3600)  # Exponential decay
                # Weight by uncertainty (higher uncertainty = more informative)
                uncertainty_weight = sample.get('uncertainty', 0.5) + 0.1
                # Weight by prediction confidence (lower confidence = more informative)
                confidence_weight = 1.0 - sample.get('confidence', 0.5) + 0.1
                
                total_weight = age_weight * uncertainty_weight * confidence_weight
                sample_weights.append(total_weight)
            
            # Normalize weights
            sample_weights = np.array(sample_weights)
            sample_weights = sample_weights / np.sum(sample_weights)
            
            # Select samples based on weights
            max_samples = min(len(all_samples), 500)
            selected_indices = np.random.choice(
                len(all_samples), 
                size=max_samples, 
                replace=False, 
                p=sample_weights
            )
            selected_samples = [all_samples[i] for i in selected_indices]
            
            # Prepare tensors with enhanced preprocessing
            features_list = [s['features'] for s in selected_samples]
            labels_list = [s['label'] for s in selected_samples]
            
            # Convert to numpy arrays first to avoid UserWarning
            features_array = np.array(features_list)
            labels_array = np.array(labels_list)
            
            features = torch.FloatTensor(features_array)
            labels = torch.LongTensor(labels_array)
            
            # Enhanced feature preprocessing
            try:
                # Robust normalization
                feature_mean = features.mean(dim=0)
                feature_std = features.std(dim=0) + 1e-8
                features = (features - feature_mean) / feature_std
                features = torch.clamp(features, -3, 3)  # Clip extreme values
            except Exception as e:
                logger.warning(f"Feature preprocessing error: {e}")
            
            # Split into train/validation with stratification
            dataset_size = len(features)
            val_size = max(1, int(dataset_size * self.validation_split))
            train_size = dataset_size - val_size
            
            # Stratified split
            threat_indices = [i for i, label in enumerate(labels) if label == 1]
            normal_indices = [i for i, label in enumerate(labels) if label == 0]
            
            val_threat_count = max(1, int(len(threat_indices) * self.validation_split))
            val_normal_count = val_size - val_threat_count
            
            if val_normal_count > len(normal_indices):
                val_normal_count = len(normal_indices)
                val_threat_count = val_size - val_normal_count
            
            val_indices = (
                np.random.choice(threat_indices, val_threat_count, replace=False).tolist() if val_threat_count > 0 else []
            ) + (
                np.random.choice(normal_indices, val_normal_count, replace=False).tolist() if val_normal_count > 0 else []
            )
            
            train_indices = [i for i in range(dataset_size) if i not in val_indices]
            
            train_features = features[train_indices]
            train_labels = labels[train_indices]
            val_features = features[val_indices]
            val_labels = labels[val_indices]
            
            # Enhanced training with multiple epochs
            self.model.train()
            total_loss = 0.0
            num_batches = 0
            
            batch_size = min(self.learning_config['batch_size'], len(train_features) // 2)
            batch_size = max(batch_size, min_batch_size)
            local_epochs = self.learning_config['local_epochs']
            
            # Learning rate warmup
            if self.training_round < 5:
                warmup_lr = self.learning_config['learning_rate'] * (self.training_round + 1) / 5
                for param_group in self.optimizer.param_groups:
                    param_group['lr'] = warmup_lr
            
            for epoch in range(local_epochs):
                epoch_loss = 0.0
                epoch_batches = 0
                
                # Shuffle training data
                perm = torch.randperm(len(train_features))
                train_features = train_features[perm]
                train_labels = train_labels[perm]
                
                for i in range(0, len(train_features), batch_size):
                    try:
                        batch_features = train_features[i:i+batch_size]
                        batch_labels = train_labels[i:i+batch_size]
                        
                        if len(batch_features) < 2:
                            continue
                        
                        # Forward pass with auxiliary outputs
                        self.optimizer.zero_grad()
                        
                        logits, _, confidence, aux_logits = self.model.forward(batch_features, return_features=True)
                        
                        # Enhanced loss computation
                        loss = self.model.compute_loss(logits, batch_labels, aux_logits, confidence)
                        
                        if torch.isnan(loss) or torch.isinf(loss):
                            logger.warning("Invalid loss detected, skipping batch")
                            continue
                        
                        # Backward pass with gradient clipping
                        loss.backward()
                        torch.nn.utils.clip_grad_norm_(
                            self.model.parameters(), 
                            self.learning_config['gradient_clip_norm']
                        )
                        
                        self.optimizer.step()
                        
                        epoch_loss += loss.item()
                        epoch_batches += 1
                        
                    except Exception as e:
                        logger.error(f"Enhanced batch training error: {e}")
                        continue
                
                if epoch_batches > 0:
                    total_loss += epoch_loss / epoch_batches
                    num_batches += 1
            
            # Enhanced validation
            if len(val_features) > 0:
                await self._perform_enhanced_validation(val_features, val_labels, total_loss / max(num_batches, 1))
            
        except Exception as e:
            logger.error(f"Enhanced model training error in {self.host_name}: {e}")
    
    async def _perform_enhanced_validation(self, val_features, val_labels, train_loss):
        """Perform enhanced validation with detailed metrics"""
        try:
            self.model.eval()
            with torch.no_grad():
                val_logits, val_features_extracted, val_confidence, _ = self.model.forward(val_features, return_features=True)
                
                if torch.isnan(val_logits).any() or torch.isinf(val_logits).any():
                    logger.warning("Invalid validation outputs detected")
                    return
                
                val_loss = self.model.compute_loss(val_logits, val_labels).item()
                val_predictions = torch.argmax(val_logits, dim=1)
                val_accuracy = (val_predictions == val_labels).float().mean().item()
                
                # Enhanced metrics calculation
                val_probs = torch.softmax(val_logits, dim=1)
                avg_confidence = torch.mean(val_confidence).item()
                prediction_entropy = -torch.sum(val_probs * torch.log(val_probs + 1e-8), dim=1).mean().item()
                
                # Calculate per-class metrics
                threat_mask = val_labels == 1
                normal_mask = val_labels == 0
                
                threat_accuracy = (val_predictions[threat_mask] == val_labels[threat_mask]).float().mean().item() if threat_mask.sum() > 0 else 0.0
                normal_accuracy = (val_predictions[normal_mask] == val_labels[normal_mask]).float().mean().item() if normal_mask.sum() > 0 else 0.0
                
                # Calculate false positive and false negative rates
                false_positives = ((val_predictions == 1) & (val_labels == 0)).sum().item()
                false_negatives = ((val_predictions == 0) & (val_labels == 1)).sum().item()
                true_positives = ((val_predictions == 1) & (val_labels == 1)).sum().item()
                true_negatives = ((val_predictions == 0) & (val_labels == 0)).sum().item()
                
                fpr = false_positives / max(false_positives + true_negatives, 1)
                fnr = false_negatives / max(false_negatives + true_positives, 1)
                
                # Store validation confusion matrix for training stats
                self.validation_confusion_matrix = {
                    'true_positives': true_positives,
                    'true_negatives': true_negatives,
                    'false_positives': false_positives,
                    'false_negatives': false_negatives
                }
                
                # Update performance metrics with thread safety
                with self.stats_lock:
                    old_accuracy = self.performance_metrics['model_accuracy']
                    self.performance_metrics['model_accuracy'] = val_accuracy
                    self.performance_metrics['model_loss'] = train_loss
                    self.performance_metrics['last_update_time'] = time.time()
                    
                    # Update history
                    self.performance_metrics['training_loss_history'].append(train_loss)
                    self.performance_metrics['validation_accuracy_history'].append(val_accuracy)
                    self.performance_metrics['false_positive_rate'] = fpr
                    
                    # Keep history manageable
                    if len(self.performance_metrics['training_loss_history']) > 50:
                        self.performance_metrics['training_loss_history'] = self.performance_metrics['training_loss_history'][-25:]
                        self.performance_metrics['validation_accuracy_history'] = self.performance_metrics['validation_accuracy_history'][-25:]
                
                # Learning rate scheduling
                if self.scheduler:
                    self.scheduler.step(val_loss)
                
                # Performance-based adaptation
                accuracy_improvement = val_accuracy - old_accuracy
                if accuracy_improvement < -0.03:  # Significant degradation
                    await self._handle_performance_degradation()
                elif accuracy_improvement > 0.05:  # Significant improvement
                    await self._handle_performance_improvement()
                
                logger.debug(f"{self.host_name} [{self.current_phase.upper()}]: Enhanced Training - "
                           f"Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}, "
                           f"Accuracy: {val_accuracy:.3f} ({accuracy_improvement:+.3f}), "
                           f"Threat Acc: {threat_accuracy:.3f}, Normal Acc: {normal_accuracy:.3f}, "
                           f"FPR: {fpr:.3f}, Confidence: {avg_confidence:.3f}")
                
        except Exception as e:
            logger.error(f"Enhanced validation error: {e}")
    
    async def _enhanced_model_validation(self):
        """Enhanced model validation for testing phase"""
        try:
            if len(self.test_data) < 4:
                return
            
            self.model.eval()
            
            # Prepare test data
            features_list = [s['features'] for s in self.test_data[-100:]]
            labels_list = [s['label'] for s in self.test_data[-100:]]
            
            # Convert to numpy arrays first to avoid UserWarning
            features_array = np.array(features_list)
            labels_array = np.array(labels_list)
            
            features = torch.FloatTensor(features_array)
            labels = torch.LongTensor(labels_array)
            
            # Enhanced validation
            with torch.no_grad():
                logits, _, confidence, _ = self.model.forward(features, return_features=True)
                
                if not (torch.isnan(logits).any() or torch.isinf(logits).any()):
                    predictions = torch.argmax(logits, dim=1)
                    accuracy = (predictions == labels).float().mean().item()
                    avg_confidence = torch.mean(confidence).item()
                    
                    # Update metrics
                    with self.stats_lock:
                        self.performance_metrics['model_accuracy'] = accuracy
                        self.performance_metrics['last_update_time'] = time.time()
                    
                    logger.debug(f"{self.host_name} [TESTING]: Enhanced Validation - "
                               f"Accuracy: {accuracy:.3f}, Confidence: {avg_confidence:.3f}")
            
        except Exception as e:
            logger.error(f"Enhanced model validation error: {e}")
    
    def _generate_enhanced_synthetic_label(self, features, prediction_info):
        """Generate enhanced synthetic training labels with better logic"""
        try:
            threat_score = 0.0
            
            # Enhanced feature-based indicators
            if len(features) >= 10:
                # Size anomalies (very small or very large)
                if features[0] < 0.1 or features[0] > 0.9:
                    threat_score += 0.2
                
                # Suspicious score (direct indicator)
                if features[8] > 0.6:
                    threat_score += 0.4
                elif features[8] > 0.4:
                    threat_score += 0.2
                
                # High entropy (potential scanning/flooding)
                if features[9] > 0.8:
                    threat_score += 0.25
                elif features[9] < 0.2:  # Very low entropy also suspicious
                    threat_score += 0.15
                
                # Protocol anomalies
                if features[5] < 0.3 or features[5] > 0.9:  # Unusual protocols
                    threat_score += 0.15
                
                # TTL anomalies
                if features[6] < 0.25 or features[6] > 0.95:  # Very low or high TTL
                    threat_score += 0.2
                
                # Connection patterns
                if features[7] > 0.8:  # High connection count
                    threat_score += 0.15
                
                # Time-based patterns
                if features[1] < 0.2 or features[1] > 0.9:  # Unusual hours
                    threat_score += 0.1
            
            # Model prediction influence (but not complete dependence)
            model_threat_prob = prediction_info.get('threat_probability', 0.5)
            model_confidence = prediction_info.get('confidence', 0.5)
            
            # Incorporate model prediction with weighting
            if model_confidence > 0.7:
                threat_score += 0.3 * model_threat_prob
            else:
                threat_score += 0.1 * model_threat_prob
            
            # Phase-specific adjustments
            if self.current_phase == "testing":
                threat_score *= 0.85  # Slightly more conservative in testing
                base_threshold = 0.55
            else:
                base_threshold = 0.5
            
            # Add controlled randomness for diversity
            noise_range = 0.08 if self.current_phase == "learning" else 0.05
            threat_score += np.random.uniform(-noise_range, noise_range)
            
            # Enhanced threshold with adaptive behavior
            performance_adjustment = 0.0
            if hasattr(self, 'performance_metrics'):
                recent_accuracy = self.performance_metrics.get('model_accuracy', 0.5)
                if recent_accuracy < 0.6:
                    performance_adjustment = 0.05  # Lower threshold if model struggling
                elif recent_accuracy > 0.8:
                    performance_adjustment = -0.05  # Raise threshold if model doing well
            
            final_threshold = base_threshold + performance_adjustment + np.random.uniform(-0.05, 0.05)
            
            return 1 if threat_score > final_threshold else 0
            
        except Exception as e:
            logger.error(f"Enhanced label generation error: {e}")
            # Phase and performance-aware fallback
            if self.current_phase == "testing":
                return np.random.choice([0, 1], p=[0.75, 0.25])
            else:
                return np.random.choice([0, 1], p=[0.65, 0.35])
    
    async def _generate_enhanced_initial_data(self):
        """Generate superior initial training data with better diversity"""
        logger.info(f"Generating enhanced initial training data for {self.host_name}")
        
        initial_samples = 200  # Increased initial data
        successful_samples = 0
        target_threat_ratio = 0.3  # Target 30% threat samples
        
        for i in range(initial_samples):
            try:
                # Generate features with controlled threat injection
                if i < initial_samples * target_threat_ratio:
                    # Generate threat-like features
                    features = self._generate_threat_like_features()
                else:
                    # Generate normal features
                    features = self.packet_analyzer.extract_features()
                
                prediction = self.model.predict_threat(features)
                label = self._generate_enhanced_synthetic_label(features, prediction)
                
                sample = {
                    'features': features.copy(),
                    'label': label,
                    'prediction': prediction['prediction'],
                    'confidence': prediction['confidence'],
                    'uncertainty': prediction.get('uncertainty', 0.5),
                    'timestamp': time.time(),
                    'firewall_action': 'allow',
                    'phase': 'initialization',
                    'threat_probability': prediction.get('threat_probability', 0.5)
                }
                
                self.training_data.append(sample)
                successful_samples += 1
                
                # Small delay for realism
                if i % 25 == 0:
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Enhanced initial data generation error: {e}")
                continue
        
        # Calculate actual threat ratio
        threat_count = sum(1 for s in self.training_data if s['label'] == 1)
        actual_threat_ratio = threat_count / max(successful_samples, 1)
        
        logger.info(f"{self.host_name}: Generated {successful_samples} enhanced initial samples "
                   f"({threat_count} threats, ratio: {actual_threat_ratio:.3f})")
    
    def _generate_threat_like_features(self):
        """Generate features that are more likely to be labeled as threats"""
        try:
            features = np.random.uniform(0.2, 0.8, 10).astype(np.float32)
            
            # Inject threat-like characteristics
            features[0] = np.random.choice([0.05, 0.95], p=[0.5, 0.5])  # Extreme sizes
            features[8] = np.random.uniform(0.6, 0.95)  # High suspicious score
            features[9] = np.random.choice([np.random.uniform(0.1, 0.3), np.random.uniform(0.8, 0.95)], p=[0.3, 0.7])  # Extreme entropy
            features[6] = np.random.choice([np.random.uniform(0.05, 0.25), np.random.uniform(0.9, 0.95)], p=[0.6, 0.4])  # Abnormal TTL
            
            return features
        except Exception as e:
            logger.error(f"Threat-like feature generation error: {e}")
            return self.packet_analyzer.extract_features()
    
    # Add the rest of the methods (performance optimization, status reporting, etc.)
    async def _performance_optimization_loop(self):
        """Continuous performance monitoring and optimization"""
        optimization_interval = 45
        
        while self.is_running:
            try:
                await asyncio.sleep(optimization_interval)
                
                if self.current_phase != "learning":
                    continue
                
                # Analyze current performance
                with self.stats_lock:
                    current_accuracy = self.performance_metrics['model_accuracy']
                    recent_losses = self.performance_metrics['training_loss_history'][-5:]
                    
                # Performance trend analysis
                if len(recent_losses) >= 3:
                    loss_trend = np.mean(recent_losses[-3:]) - np.mean(recent_losses[-5:-2])
                    
                    if loss_trend > 0.01:  # Loss increasing
                        await self._apply_performance_optimization("loss_increase")
                    elif current_accuracy < 0.6:  # Low accuracy
                        await self._apply_performance_optimization("low_accuracy")
                    elif current_accuracy > 0.85:  # High accuracy
                        await self._apply_performance_optimization("high_accuracy")
                
            except Exception as e:
                logger.error(f"Performance optimization loop error: {e}")
    
    async def _apply_performance_optimization(self, optimization_type):
        """Apply specific performance optimization strategies"""
        try:
            if optimization_type == "loss_increase":
                # Reduce learning rate and increase regularization
                new_lr = max(0.0001, self.learning_config['learning_rate'] * 0.8)
                await self.update_learning_rate(new_lr)
                
                new_dropout = min(0.4, self.learning_config['dropout_rate'] * 1.2)
                await self.update_dropout_rate(new_dropout)
                
                logger.info(f"{self.host_name}: Applied loss increase optimization")
                
            elif optimization_type == "low_accuracy":
                # Increase learning rate slightly and reduce regularization
                new_lr = min(0.02, self.learning_config['learning_rate'] * 1.1)
                await self.update_learning_rate(new_lr)
                
                new_dropout = max(0.05, self.learning_config['dropout_rate'] * 0.9)
                await self.update_dropout_rate(new_dropout)
                
                logger.info(f"{self.host_name}: Applied low accuracy optimization")
                
            elif optimization_type == "high_accuracy":
                # Fine-tune with lower learning rate for stability
                new_lr = max(0.0005, self.learning_config['learning_rate'] * 0.9)
                await self.update_learning_rate(new_lr)
                
                logger.info(f"{self.host_name}: Applied high accuracy optimization")
                
        except Exception as e:
            logger.error(f"Performance optimization application error: {e}")

    async def _adaptive_hyperparameter_loop(self):
        """Adaptive hyperparameter tuning based on performance"""
        adaptation_interval = 60
        
        while self.is_running:
            try:
                await asyncio.sleep(adaptation_interval)
                
                if self.current_phase != "learning" or len(self.performance_metrics['validation_accuracy_history']) < 3:
                    continue
                
                # Analyze performance trends
                recent_accuracies = self.performance_metrics['validation_accuracy_history'][-5:]
                recent_losses = self.performance_metrics['training_loss_history'][-5:]
                
                if len(recent_accuracies) >= 3 and len(recent_losses) >= 3:
                    accuracy_trend = np.mean(recent_accuracies[-3:]) - np.mean(recent_accuracies[-5:-2])
                    loss_trend = np.mean(recent_losses[-3:]) - np.mean(recent_losses[-5:-2])
                    
                    await self._adaptive_hyperparameter_adjustment(accuracy_trend, loss_trend)
                
            except Exception as e:
                logger.error(f"Adaptive hyperparameter loop error: {e}")
    
    async def _adaptive_hyperparameter_adjustment(self, accuracy_trend, loss_trend):
        """Perform adaptive hyperparameter adjustments"""
        try:
            adjustments = []
            
            # Learning rate adjustments
            if accuracy_trend < -0.02 and loss_trend > 0.005:  # Degrading performance
                new_lr = max(0.0001, self.learning_config['learning_rate'] * 0.7)
                await self.update_learning_rate(new_lr)
                adjustments.append(f"LR: {new_lr:.4f}")
                
            elif accuracy_trend > 0.03 and loss_trend < -0.01:  # Improving performance
                new_lr = min(0.02, self.learning_config['learning_rate'] * 1.1)
                await self.update_learning_rate(new_lr)
                adjustments.append(f"LR: {new_lr:.4f}")
            
            # Dropout adjustments
            current_acc = self.performance_metrics['model_accuracy']
            if current_acc < 0.65 and accuracy_trend < 0:  # Struggling model
                new_dropout = max(0.05, self.learning_config['dropout_rate'] * 0.8)
                await self.update_dropout_rate(new_dropout)
                adjustments.append(f"Dropout: {new_dropout:.3f}")
                
            elif current_acc > 0.85 and accuracy_trend < 0.01:  # Potential overfitting
                new_dropout = min(0.35, self.learning_config['dropout_rate'] * 1.2)
                await self.update_dropout_rate(new_dropout)
                adjustments.append(f"Dropout: {new_dropout:.3f}")
            
            if adjustments:
                logger.info(f"{self.host_name}: Adaptive adjustments - {', '.join(adjustments)}")
                
        except Exception as e:
            logger.error(f"Adaptive hyperparameter adjustment error: {e}")
    
    async def update_learning_rate(self, new_lr):
        """Update learning rate with enhanced validation"""
        try:
            if 0.0001 <= new_lr <= 0.05:
                old_lr = self.learning_config['learning_rate']
                self.learning_config['learning_rate'] = new_lr
                
                for param_group in self.optimizer.param_groups:
                    param_group['lr'] = new_lr
                
                self.hyperparameter_history['learning_rates'].append(new_lr)
                logger.debug(f"{self.host_name}: Learning rate updated: {old_lr:.4f} -> {new_lr:.4f}")
            else:
                logger.warning(f"{self.host_name}: Invalid learning rate {new_lr}")
                
        except Exception as e:
            logger.error(f"Learning rate update error: {e}")
    
    async def update_dropout_rate(self, new_dropout):
        """Update dropout rate with enhanced validation"""
        try:
            if 0.0 <= new_dropout <= 0.5:
                old_dropout = self.learning_config['dropout_rate']
                self.learning_config['dropout_rate'] = new_dropout
                
                # Update model dropout layers
                self.model.update_dropout_rate(new_dropout)
                
                self.hyperparameter_history['dropout_rates'].append(new_dropout)
                logger.debug(f"{self.host_name}: Dropout rate updated: {old_dropout:.3f} -> {new_dropout:.3f}")
            else:
                logger.warning(f"{self.host_name}: Invalid dropout rate {new_dropout}")
                
        except Exception as e:
            logger.error(f"Dropout rate update error: {e}")
    
    async def update_batch_size(self, new_batch_size):
        """Update batch size with enhanced validation"""
        try:
            if 4 <= new_batch_size <= 128:
                old_batch_size = self.learning_config['batch_size']
                self.learning_config['batch_size'] = new_batch_size
                
                self.hyperparameter_history['batch_sizes'].append(new_batch_size)
                logger.debug(f"{self.host_name}: Batch size updated: {old_batch_size} -> {new_batch_size}")
            else:
                logger.warning(f"{self.host_name}: Invalid batch size {new_batch_size}")
                
        except Exception as e:
            logger.error(f"Batch size update error: {e}")
    
    async def _handle_performance_degradation(self):
        """Handle significant performance degradation"""
        try:
            logger.warning(f"{self.host_name}: Performance degradation detected, applying recovery measures")
            
            # Reduce learning rate aggressively
            new_lr = max(0.0001, self.learning_config['learning_rate'] * 0.5)
            await self.update_learning_rate(new_lr)
            
            # Increase dropout for better generalization
            new_dropout = min(0.4, self.learning_config['dropout_rate'] * 1.3)
            await self.update_dropout_rate(new_dropout)
            
            # Reduce batch size for more frequent updates
            new_batch_size = max(8, int(self.learning_config['batch_size'] * 0.75))
            await self.update_batch_size(new_batch_size)
            
            # Record optimization action
            self.hyperparameter_history['optimization_history'].append({
                'timestamp': time.time(),
                'action': 'performance_degradation_recovery',
                'changes': {'lr': new_lr, 'dropout': new_dropout, 'batch_size': new_batch_size}
            })
            
        except Exception as e:
            logger.error(f"Performance degradation handling error: {e}")
    
    async def _handle_performance_improvement(self):
        """Handle significant performance improvement"""
        try:
            logger.info(f"{self.host_name}: Performance improvement detected, fine-tuning parameters")
            
            # Slightly reduce learning rate for stability
            new_lr = max(0.0005, self.learning_config['learning_rate'] * 0.9)
            await self.update_learning_rate(new_lr)
            
            # Record optimization action
            self.hyperparameter_history['optimization_history'].append({
                'timestamp': time.time(),
                'action': 'performance_improvement_tuning',
                'changes': {'lr': new_lr}
            })
            
        except Exception as e:
            logger.error(f"Performance improvement handling error: {e}")
    
    async def _enhanced_status_reporting_loop(self):
        """Enhanced status reporting with comprehensive metrics"""
        report_interval = 30
        
        while self.is_running:
            try:
                await asyncio.sleep(report_interval)
                
                # Collect comprehensive statistics
                analyzer_stats = self.packet_analyzer.get_analyzer_stats()
                firewall_stats = self.firewall_manager.get_firewall_stats()
                model_info = self.model.get_model_info()
                
                # Calculate additional metrics
                with self.stats_lock:
                    avg_confidence = np.mean(self.performance_metrics['confidence_scores']) if self.performance_metrics['confidence_scores'] else 0.5
                    threat_detection_rate = self.performance_metrics['threats_detected'] / max(self.performance_metrics['packets_processed'], 1)
                
                # Log enhanced status
                logger.info(f"{self.host_name} Enhanced Status [{self.current_phase.upper()}]:")
                logger.info(f"  Round: {self.training_round}, Accuracy: {self.performance_metrics['model_accuracy']:.3f}")
                logger.info(f"  Packets: {self.performance_metrics['packets_processed']}, "
                          f"Threats: {self.performance_metrics['threats_detected']} "
                          f"(Rate: {threat_detection_rate:.3f})")
                logger.info(f"  Confidence: {avg_confidence:.3f}, "
                          f"FPR: {self.performance_metrics.get('false_positive_rate', 0):.3f}")
                logger.info(f"  Learning: LR={self.get_current_learning_rate():.4f}, "
                          f"Dropout={self.learning_config['dropout_rate']:.3f}, "
                          f"Batch={self.learning_config['batch_size']}")
                
            except Exception as e:
                logger.error(f"Enhanced status reporting error in {self.host_name}: {e}")
    
    async def _enhanced_data_management_loop(self):
        """Enhanced data management with intelligent cleanup"""
        cleanup_interval = 90
        
        while self.is_running:
            try:
                await asyncio.sleep(cleanup_interval)
                
                # Enhanced data cleanup based on phase and performance
                if self.current_phase == "learning":
                    if len(self.training_data) > self.max_training_samples:
                        # Keep diverse and recent samples
                        await self._intelligent_data_cleanup()
                
                elif self.current_phase == "testing":
                    # Maintain reasonable test data size
                    if len(self.test_data) > 1000:
                        self.test_data = self.test_data[-500:]
                        logger.debug(f"{self.host_name}: Cleaned test data to {len(self.test_data)} samples")
                
                # Memory optimization
                if len(self.performance_metrics['training_loss_history']) > 100:
                    self.performance_metrics['training_loss_history'] = self.performance_metrics['training_loss_history'][-50:]
                    self.performance_metrics['validation_accuracy_history'] = self.performance_metrics['validation_accuracy_history'][-50:]
                
                # Reset counters if they get too large
                if self.performance_metrics['packets_processed'] > 50000:
                    await self._reset_performance_counters()
                
            except Exception as e:
                logger.error(f"Enhanced data management error in {self.host_name}: {e}")
    
    async def _intelligent_data_cleanup(self):
        """Intelligent data cleanup preserving valuable samples"""
        try:
            target_size = int(self.max_training_samples * 0.8)
            current_size = len(self.training_data)
            
            if current_size <= target_size:
                return
            
            # Categorize samples by importance
            high_value_samples = []
            medium_value_samples = []
            low_value_samples = []
            
            current_time = time.time()
            
            for sample in self.training_data:
                value_score = 0
                
                # Recent samples are more valuable
                age = current_time - sample['timestamp']
                if age < 3600:  # Last hour
                    value_score += 3
                elif age < 7200:  # Last 2 hours
                    value_score += 2
                else:
                    value_score += 1
                
                # Uncertain samples are more valuable for learning
                uncertainty = sample.get('uncertainty', 0.5)
                if uncertainty > 0.7:
                    value_score += 2
                elif uncertainty > 0.5:
                    value_score += 1
                
                # Threat samples are more valuable (usually less common)
                if sample['label'] == 1:
                    value_score += 2
                
                # Misclassified samples are valuable
                if sample['prediction'] != sample['label']:
                    value_score += 2
                
                # Categorize by total score
                if value_score >= 6:
                    high_value_samples.append(sample)
                elif value_score >= 4:
                    medium_value_samples.append(sample)
                else:
                    low_value_samples.append(sample)
            
            # Keep all high-value, sample medium-value, minimal low-value
            kept_samples = high_value_samples.copy()
            
            remaining_slots = target_size - len(kept_samples)
            if remaining_slots > 0 and medium_value_samples:
                medium_keep_count = min(len(medium_value_samples), remaining_slots)
                kept_samples.extend(np.random.choice(
                    medium_value_samples, 
                    medium_keep_count, 
                    replace=False
                ).tolist())
                remaining_slots -= medium_keep_count
            
            if remaining_slots > 0 and low_value_samples:
                low_keep_count = min(len(low_value_samples), remaining_slots)
                kept_samples.extend(np.random.choice(
                    low_value_samples, 
                    low_keep_count, 
                    replace=False
                ).tolist())
            
            # Update training data
            self.training_data = kept_samples
            
            logger.info(f"{self.host_name}: Intelligent cleanup - kept {len(kept_samples)} of {current_size} samples "
                       f"(High: {len(high_value_samples)}, Medium: {len([s for s in kept_samples if s in medium_value_samples])}, "
                       f"Low: {len([s for s in kept_samples if s in low_value_samples])})")
            
        except Exception as e:
            logger.error(f"Intelligent data cleanup error: {e}")
    
    async def _reset_performance_counters(self):
        """Reset performance counters while preserving important metrics"""
        try:
            with self.stats_lock:
                # Preserve important metrics
                preserved_accuracy = self.performance_metrics['model_accuracy']
                preserved_loss = self.performance_metrics['model_loss']
                preserved_phase_history = self.performance_metrics['phase_accuracy_history']
                
                # Reset counters
                self.performance_metrics.update({
                    'packets_processed': 0,
                    'threats_detected': 0,
                    'model_accuracy': preserved_accuracy,
                    'model_loss': preserved_loss,
                    'training_loss_history': self.performance_metrics['training_loss_history'][-10:],
                    'validation_accuracy_history': self.performance_metrics['validation_accuracy_history'][-10:],
                    'confidence_scores': self.performance_metrics['confidence_scores'][-20:],
                    'last_update_time': time.time(),
                    'phase_accuracy_history': preserved_phase_history,
                    'gradient_norms': [],
                    'learning_curves': {'train_loss': [], 'val_accuracy': []},
                    'threat_detection_rate': 0.0,
                    'false_positive_rate': 0.0
                })
            
            # Reset component statistics
            self.packet_analyzer.reset_stats()
            self.firewall_manager.reset_stats()
            
            logger.info(f"{self.host_name}: Performance counters reset while preserving key metrics")
            
        except Exception as e:
            logger.error(f"Performance counter reset error: {e}")
    
    async def _log_training_progress(self):
        """Log detailed training progress"""
        try:
            with self.stats_lock:
                recent_acc = self.performance_metrics['validation_accuracy_history'][-5:] if len(self.performance_metrics['validation_accuracy_history']) >= 5 else []
                recent_loss = self.performance_metrics['training_loss_history'][-5:] if len(self.performance_metrics['training_loss_history']) >= 5 else []
                
                if recent_acc and recent_loss:
                    acc_trend = "↑" if len(recent_acc) >= 2 and recent_acc[-1] > recent_acc[-2] else "↓"
                    loss_trend = "↓" if len(recent_loss) >= 2 and recent_loss[-1] < recent_loss[-2] else "↑"
                    
                    logger.info(f"{self.host_name} Training Progress (Round {self.training_round}):")
                    logger.info(f"  Accuracy: {self.performance_metrics['model_accuracy']:.3f} {acc_trend}")
                    logger.info(f"  Loss: {self.performance_metrics['model_loss']:.4f} {loss_trend}")
                    logger.info(f"  Data: {len(self.training_data)} train, {len(self.validation_data)} val")
                    logger.info(f"  Hyperparams: LR={self.get_current_learning_rate():.4f}, "
                              f"Dropout={self.learning_config['dropout_rate']:.3f}")
                    
        except Exception as e:
            logger.error(f"Training progress logging error: {e}")
    
    def update_phase(self, new_phase):
        """Update the current operational phase - legacy compatibility"""
        try:
            if new_phase != self.current_phase:
                logger.info(f"{self.host_name}: Phase update signal received: {self.current_phase} -> {new_phase}")
                asyncio.create_task(self.on_phase_change(new_phase))
        except Exception as e:
            logger.error(f"Phase update error: {e}")
    
    def get_model_weights(self):
        """Get enhanced model weights for federated averaging"""
        try:
            return self.model.get_weights()
        except Exception as e:
            logger.error(f"Error getting enhanced model weights from {self.host_name}: {e}")
            return {}
    
    def set_model_weights(self, weights):
        """Set enhanced model weights from federated averaging"""
        try:
            self.model.set_weights(weights)
            logger.debug(f"{self.host_name}: Updated enhanced model weights from federated averaging")
        except Exception as e:
            logger.error(f"Error setting enhanced model weights for {self.host_name}: {e}")
    
    def get_training_stats(self):
        """Get comprehensive enhanced training statistics"""
        try:
            with self.stats_lock:
                threat_ratio = self.performance_metrics['threats_detected'] / max(self.performance_metrics['packets_processed'], 1)
                avg_confidence = np.mean(self.performance_metrics['confidence_scores']) if self.performance_metrics['confidence_scores'] else 0.5
                
                # Get confusion matrix data from firewall manager
                firewall_stats = self.firewall_manager.get_firewall_stats()
                confusion_matrix = {
                    'true_positives': firewall_stats.get('true_positives', 0),
                    'true_negatives': firewall_stats.get('true_negatives', 0),
                    'false_positives': firewall_stats.get('false_positives', 0),
                    'false_negatives': firewall_stats.get('false_negatives', 0)
                }
                
                # Add validation-based confusion matrix if available
                if hasattr(self, 'validation_confusion_matrix'):
                    val_cm = self.validation_confusion_matrix
                    confusion_matrix['true_positives'] += val_cm.get('true_positives', 0)
                    confusion_matrix['true_negatives'] += val_cm.get('true_negatives', 0)
                    confusion_matrix['false_positives'] += val_cm.get('false_positives', 0)
                    confusion_matrix['false_negatives'] += val_cm.get('false_negatives', 0)
                
                return {
                    'host': self.host_name,
                    'host_ip': self.host_ip,
                    'client_id': self.client_id,
                    'current_phase': self.current_phase,
                    'training_round': self.training_round,
                    'performance_metrics': {
                        **self.performance_metrics,
                        'average_confidence': avg_confidence,
                        'threat_detection_rate': threat_ratio,
                        'confusion_matrix': confusion_matrix
                    },
                    'hyperparameters': {
                        'current_config': self.learning_config.copy(),
                        'history': self.hyperparameter_history.copy()
                    },
                    'data_stats': {
                        'training_samples': len(self.training_data),
                        'validation_samples': len(self.validation_data),
                        'test_samples': len(self.test_data),
                        'threat_ratio': threat_ratio
                    },
                    'firewall_stats': firewall_stats,
                    'analyzer_stats': self.packet_analyzer.get_analyzer_stats(),
                    'model_info': self.model.get_model_info()
                }
        except Exception as e:
            logger.error(f"Error getting enhanced training stats: {e}")
            return {'host': self.host_name, 'error': str(e)}