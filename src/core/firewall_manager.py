import logging
import threading
import time
import numpy as np
from typing import Dict, List, Set, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class SimpleFirewallManager:
    """ENHANCED firewall manager with superior threat detection and adaptive thresholds"""
    
    def __init__(self, config):
        try:
            self.config = config
            self.blocked_ips: Set[str] = set()
            self.blocked_ports: Set[int] = set(config.get('firewall', {}).get('blacklist_ports', []))
            self.whitelist_ips: Set[str] = set(config.get('firewall', {}).get('whitelist_ips', []))
            self.enable_blocking = config.get('firewall', {}).get('enable_blocking', False)
            self.max_blocked_ips = config.get('firewall', {}).get('max_blocked_ips', 100)
            
            # Enhanced statistics with thread safety
            self.stats = {
                'packets_analyzed': 0,
                'threats_detected': 0,
                'packets_blocked': 0,
                'false_positives': 0,
                'true_positives': 0,
                'false_negatives': 0,
                'true_negatives': 0
            }
            
            # Enhanced threat detection
            self.threat_history = deque(maxlen=1000)
            self.ip_statistics = defaultdict(lambda: {
                'packets': 0, 'threats': 0, 'blocked': 0, 
                'last_seen': time.time(), 'threat_score': 0.0
            })
            
            # Adaptive thresholds
            self.adaptive_config = config.get('firewall', {}).get('adaptation', {})
            self.current_threat_threshold = config.get('security', {}).get('threat_threshold', 0.6)
            self.current_block_threshold = config.get('security', {}).get('block_threshold', 0.7)
            self.base_threat_threshold = self.current_threat_threshold
            self.base_block_threshold = self.current_block_threshold
            
            # Performance tracking
            self.detection_accuracy_window = deque(maxlen=100)
            self.false_positive_window = deque(maxlen=100)
            
            # Thread safety
            self.lock = threading.RLock()
            
            logger.info(f"Enhanced firewall manager initialized - Blocking: {self.enable_blocking}, "
                       f"Threat threshold: {self.current_threat_threshold}, "
                       f"Block threshold: {self.current_block_threshold}")
            
        except Exception as e:
            logger.error(f"Enhanced firewall manager initialization error: {e}")
            # Set enhanced safe defaults
            self._initialize_safe_defaults(config)
    
    def _initialize_safe_defaults(self, config):
        """Initialize safe defaults in case of initialization errors"""
        self.config = config or {}
        self.blocked_ips = set()
        self.blocked_ports = set([4444, 6666, 1234, 31337])
        self.whitelist_ips = set()
        self.enable_blocking = False
        self.max_blocked_ips = 100
        self.stats = {
            'packets_analyzed': 0, 'threats_detected': 0, 'packets_blocked': 0,
            'false_positives': 0, 'true_positives': 0, 'false_negatives': 0, 'true_negatives': 0
        }
        self.threat_history = deque(maxlen=1000)
        self.ip_statistics = defaultdict(lambda: {
            'packets': 0, 'threats': 0, 'blocked': 0, 
            'last_seen': time.time(), 'threat_score': 0.0
        })
        self.adaptive_config = {}
        self.current_threat_threshold = 0.6
        self.current_block_threshold = 0.7
        self.base_threat_threshold = 0.6
        self.base_block_threshold = 0.7
        self.detection_accuracy_window = deque(maxlen=100)
        self.false_positive_window = deque(maxlen=100)
        self.lock = threading.RLock()
    
    def analyze_packet(self, features, model_prediction, ground_truth=None):
        """Enhanced packet analysis with adaptive thresholds and detailed metrics"""
        
        try:
            with self.lock:
                self.stats['packets_analyzed'] += 1
                
                # Extract enhanced threat information
                is_threat = model_prediction.get('is_threat', False)
                confidence = model_prediction.get('confidence', 0.0)
                threat_probability = model_prediction.get('threat_probability', 0.0)
                uncertainty = model_prediction.get('uncertainty', 0.5)
                
                # Validate and normalize confidence values
                confidence = max(0.0, min(1.0, confidence))
                threat_probability = max(0.0, min(1.0, threat_probability))
                uncertainty = max(0.0, min(1.0, uncertainty))
                
                # Enhanced threat detection with adaptive thresholds
                current_time = time.time()
                adaptive_threat_threshold = self._calculate_adaptive_threshold('threat', current_time)
                adaptive_block_threshold = self._calculate_adaptive_threshold('block', current_time)
                
                # Multi-factor threat assessment
                threat_factors = self._assess_threat_factors(features, model_prediction, confidence)
                final_threat_score = self._calculate_final_threat_score(
                    threat_probability, confidence, uncertainty, threat_factors
                )
                
                # Decision making
                action_info = {
                    'is_threat': is_threat,
                    'confidence': confidence,
                    'threat_probability': threat_probability,
                    'uncertainty': uncertainty,
                    'final_threat_score': final_threat_score,
                    'adaptive_thresholds': {
                        'threat': adaptive_threat_threshold,
                        'block': adaptive_block_threshold
                    },
                    'threat_factors': threat_factors,
                    'action': 'allow',
                    'timestamp': current_time
                }
                
                # Enhanced threat detection logic
                if final_threat_score > adaptive_threat_threshold:
                    self.stats['threats_detected'] += 1
                    action_info['action'] = 'detect'
                    
                    # Enhanced blocking logic
                    if (self.enable_blocking and 
                        final_threat_score > adaptive_block_threshold and
                        confidence > 0.5):  # Minimum confidence for blocking
                        
                        action_info['action'] = 'block'
                        self.stats['packets_blocked'] += 1
                        
                        # Execute enhanced blocking action
                        self._execute_enhanced_blocking(features, action_info)
                
                # Update threat history and statistics
                self._update_threat_history(action_info, features, ground_truth)
                
                # Adaptive threshold adjustment
                if len(self.threat_history) % 50 == 0:  # Every 50 packets
                    self._adjust_adaptive_thresholds()
                
                return action_info
                
        except Exception as e:
            logger.error(f"Enhanced packet analysis error: {e}")
            return {
                'action': 'allow', 'error': str(e), 'is_threat': False,
                'confidence': 0.5, 'threat_probability': 0.5, 'uncertainty': 0.5,
                'final_threat_score': 0.5, 'timestamp': time.time()
            }
    
    def _assess_threat_factors(self, features, model_prediction, confidence):
        """Assess additional threat factors beyond model prediction"""
        try:
            factors = {
                'size_anomaly': 0.0,
                'port_suspicion': 0.0,
                'ip_reputation': 0.0,
                'temporal_anomaly': 0.0,
                'protocol_anomaly': 0.0
            }
            
            if len(features) >= 10:
                # Size-based anomaly detection
                packet_size_norm = features[0]
                if packet_size_norm < 0.1 or packet_size_norm > 0.9:
                    factors['size_anomaly'] = 0.3
                elif packet_size_norm < 0.2 or packet_size_norm > 0.8:
                    factors['size_anomaly'] = 0.15
                
                # Protocol anomaly detection
                protocol_norm = features[5] if len(features) > 5 else 0.5
                if protocol_norm < 0.3 or protocol_norm > 0.85:
                    factors['protocol_anomaly'] = 0.2
                
                # TTL anomaly detection
                ttl_norm = features[6] if len(features) > 6 else 0.5
                if ttl_norm < 0.25 or ttl_norm > 0.95:
                    factors['temporal_anomaly'] = 0.15
                
                # High connection count (potential scanning)
                connections_norm = features[7] if len(features) > 7 else 0.5
                if connections_norm > 0.8:
                    factors['ip_reputation'] = 0.2
                elif connections_norm > 0.6:
                    factors['ip_reputation'] = 0.1
            
            # Port-based suspicion (simulated)
            if 'src_port' in model_prediction:
                port = model_prediction.get('src_port', 0)
                if port in self.blocked_ports:
                    factors['port_suspicion'] = 0.4
                elif port > 60000:
                    factors['port_suspicion'] = 0.1
            
            return factors
            
        except Exception as e:
            logger.error(f"Threat factor assessment error: {e}")
            return {
                'size_anomaly': 0.0, 'port_suspicion': 0.0, 'ip_reputation': 0.0,
                'temporal_anomaly': 0.0, 'protocol_anomaly': 0.0
            }
    
    def _calculate_final_threat_score(self, threat_prob, confidence, uncertainty, threat_factors):
        """Calculate final threat score combining multiple factors"""
        try:
            # Base score from model
            base_score = threat_prob * confidence
            
            # Uncertainty penalty (higher uncertainty reduces confidence in threat detection)
            uncertainty_penalty = uncertainty * 0.1
            
            # Additional threat factors
            factor_score = sum(threat_factors.values())
            
            # Combine scores with weights
            final_score = (
                0.6 * base_score +           # Model prediction (primary)
                0.3 * factor_score +         # Additional factors
                0.1 * (1 - uncertainty)      # Certainty bonus
            ) - uncertainty_penalty
            
            return max(0.0, min(1.0, final_score))
            
        except Exception as e:
            logger.error(f"Final threat score calculation error: {e}")
            return threat_prob  # Fallback to basic threat probability
    
    def _calculate_adaptive_threshold(self, threshold_type, current_time):
        """Calculate adaptive threshold based on recent performance"""
        try:
            if threshold_type == 'threat':
                base_threshold = self.base_threat_threshold
            else:  # 'block'
                base_threshold = self.base_block_threshold
            
            # No adaptation if disabled
            if not self.adaptive_config.get('dynamic_thresholds', False):
                return base_threshold
            
            # Calculate recent false positive rate
            if len(self.false_positive_window) >= 10:
                recent_fp_rate = sum(self.false_positive_window) / len(self.false_positive_window)
                max_fp_rate = self.adaptive_config.get('false_positive_threshold', 0.1)
                
                # Adjust threshold if FP rate is too high
                if recent_fp_rate > max_fp_rate:
                    adjustment = min(0.1, (recent_fp_rate - max_fp_rate) * 0.5)
                    return min(0.9, base_threshold + adjustment)
                elif recent_fp_rate < max_fp_rate * 0.5:  # Very low FP rate, can be more aggressive
                    adjustment = min(0.05, (max_fp_rate - recent_fp_rate) * 0.3)
                    return max(0.3, base_threshold - adjustment)
            
            return base_threshold
            
        except Exception as e:
            logger.error(f"Adaptive threshold calculation error: {e}")
            return base_threshold if 'base_threshold' in locals() else 0.6
    
    def _execute_enhanced_blocking(self, features, action_info):
        """Execute enhanced blocking action with IP reputation tracking"""
        try:
            # Generate realistic source IP from features
            if len(features) >= 4:
                src_ip_octet = max(1, min(254, int(features[3] * 253) + 1))
                
                # Add some realism based on threat score
                if action_info['final_threat_score'] > 0.8:
                    # High threat - could be external
                    src_ip_octet = np.random.randint(100, 200)
                
                simulated_src_ip = f"10.0.0.{src_ip_octet}"
            else:
                simulated_src_ip = "10.0.0.100"
            
            # Check whitelist
            if simulated_src_ip in self.whitelist_ips:
                logger.warning(f"Enhanced blocking: IP {simulated_src_ip} in whitelist, not blocking")
                action_info['whitelisted'] = True
                return
            
            # Update IP statistics
            ip_stats = self.ip_statistics[simulated_src_ip]
            ip_stats['packets'] += 1
            ip_stats['threats'] += 1
            ip_stats['last_seen'] = time.time()
            ip_stats['threat_score'] = max(ip_stats['threat_score'], action_info['final_threat_score'])
            
            # Enhanced blocking logic
            should_block = self._should_block_ip(simulated_src_ip, action_info)
            
            if should_block:
                self.blocked_ips.add(simulated_src_ip)
                ip_stats['blocked'] += 1
                
                # Maintain size limit with intelligent removal
                if len(self.blocked_ips) > self.max_blocked_ips:
                    self._intelligent_blocked_ip_cleanup()
                
                logger.info(f"ENHANCED BLOCK: {simulated_src_ip} - "
                          f"Threat Score: {action_info['final_threat_score']:.3f}, "
                          f"Confidence: {action_info['confidence']:.3f}, "
                          f"Factors: {sum(action_info['threat_factors'].values()):.3f}")
                
                action_info['blocked_ip'] = simulated_src_ip
                action_info['block_reason'] = self._generate_block_reason(action_info)
            else:
                action_info['block_decision'] = 'threshold_not_met'
                
        except Exception as e:
            logger.error(f"Enhanced blocking execution error: {e}")
            action_info['block_error'] = str(e)
    
    def _should_block_ip(self, ip_address, action_info):
        """Enhanced decision logic for IP blocking"""
        try:
            ip_stats = self.ip_statistics[ip_address]
            
            # Basic threshold check
            if action_info['final_threat_score'] < self.current_block_threshold:
                return False
            
            # Check if IP is already causing problems
            if ip_stats['packets'] > 1:
                threat_ratio = ip_stats['threats'] / ip_stats['packets']
                if threat_ratio > 0.7:  # High threat ratio
                    return True
                elif threat_ratio < 0.3:  # Low threat ratio, be more cautious
                    return action_info['final_threat_score'] > (self.current_block_threshold + 0.1)
            
            # High confidence and high threat score
            if (action_info['confidence'] > 0.8 and 
                action_info['final_threat_score'] > 0.8):
                return True
            
            # Multiple threat factors
            total_factors = sum(action_info['threat_factors'].values())
            if total_factors > 0.5:
                return True
            
            # Default to basic threshold
            return action_info['final_threat_score'] > self.current_block_threshold
            
        except Exception as e:
            logger.error(f"Block decision error: {e}")
            return action_info['final_threat_score'] > self.current_block_threshold
    
    def _generate_block_reason(self, action_info):
        """Generate human-readable block reason"""
        try:
            reasons = []
            
            if action_info['final_threat_score'] > 0.8:
                reasons.append("high_threat_score")
            if action_info['confidence'] > 0.8:
                reasons.append("high_confidence")
            
            # Check threat factors
            factors = action_info['threat_factors']
            if factors['size_anomaly'] > 0.2:
                reasons.append("size_anomaly")
            if factors['port_suspicion'] > 0.2:
                reasons.append("suspicious_port")
            if factors['ip_reputation'] > 0.1:
                reasons.append("reputation_issue")
            if factors['protocol_anomaly'] > 0.1:
                reasons.append("protocol_anomaly")
            
            return ",".join(reasons) if reasons else "threshold_exceeded"
            
        except Exception as e:
            logger.error(f"Block reason generation error: {e}")
            return "unknown"
    
    def _intelligent_blocked_ip_cleanup(self):
        """Intelligent cleanup of blocked IPs based on threat scores and age"""
        try:
            if len(self.blocked_ips) <= self.max_blocked_ips:
                return
            
            current_time = time.time()
            ip_scores = []
            
            # Score each blocked IP
            for ip in self.blocked_ips:
                if ip in self.ip_statistics:
                    stats = self.ip_statistics[ip]
                    
                    # Calculate retention score (higher = keep longer)
                    age_hours = (current_time - stats['last_seen']) / 3600
                    threat_score = stats['threat_score']
                    threat_ratio = stats['threats'] / max(stats['packets'], 1)
                    
                    # Scoring factors
                    recency_score = max(0, 1 - age_hours / 24)  # Decay over 24 hours
                    threat_score_weight = threat_score
                    frequency_score = min(1, threat_ratio)
                    
                    retention_score = (0.4 * recency_score + 
                                     0.4 * threat_score_weight + 
                                     0.2 * frequency_score)
                    
                    ip_scores.append((ip, retention_score))
                else:
                    # No statistics, low retention score
                    ip_scores.append((ip, 0.1))
            
            # Sort by retention score (ascending - lowest scores removed first)
            ip_scores.sort(key=lambda x: x[1])
            
            # Remove lowest scoring IPs
            removal_count = len(self.blocked_ips) - self.max_blocked_ips + 10  # Remove a few extra
            for i in range(min(removal_count, len(ip_scores))):
                ip_to_remove = ip_scores[i][0]
                self.blocked_ips.discard(ip_to_remove)
                logger.debug(f"Enhanced cleanup: removed {ip_to_remove} (score: {ip_scores[i][1]:.3f})")
            
        except Exception as e:
            logger.error(f"Intelligent blocked IP cleanup error: {e}")
            # Fallback to simple FIFO removal
            if len(self.blocked_ips) > self.max_blocked_ips:
                blocked_list = list(self.blocked_ips)
                oldest_ip = blocked_list[0]
                self.blocked_ips.remove(oldest_ip)
    
    def _update_threat_history(self, action_info, features, ground_truth=None):
        """Update threat history and performance metrics"""
        try:
            threat_record = {
                'timestamp': action_info['timestamp'],
                'threat_score': action_info['final_threat_score'],
                'confidence': action_info['confidence'],
                'action': action_info['action'],
                'ground_truth': ground_truth
            }
            
            self.threat_history.append(threat_record)
            
            # Update performance metrics if ground truth is available
            if ground_truth is not None:
                predicted_threat = action_info['action'] in ['detect', 'block']
                actual_threat = ground_truth == 1
                
                if predicted_threat and actual_threat:
                    self.stats['true_positives'] += 1
                elif predicted_threat and not actual_threat:
                    self.stats['false_positives'] += 1
                    self.false_positive_window.append(1)
                elif not predicted_threat and actual_threat:
                    self.stats['false_negatives'] += 1
                else:  # not predicted_threat and not actual_threat
                    self.stats['true_negatives'] += 1
                
                if not predicted_threat or actual_threat:
                    self.false_positive_window.append(0)
                
                # Calculate and store accuracy
                if len(self.threat_history) > 10:
                    recent_records = [r for r in list(self.threat_history)[-50:] if r['ground_truth'] is not None]
                    if recent_records:
                        correct_predictions = sum(1 for r in recent_records 
                                                if (r['action'] in ['detect', 'block']) == (r['ground_truth'] == 1))
                        accuracy = correct_predictions / len(recent_records)
                        self.detection_accuracy_window.append(accuracy)
            
        except Exception as e:
            logger.error(f"Threat history update error: {e}")
    
    def _adjust_adaptive_thresholds(self):
        """Adjust adaptive thresholds based on recent performance"""
        try:
            if not self.adaptive_config.get('dynamic_thresholds', False):
                return
            
            # Calculate recent performance metrics
            if len(self.false_positive_window) >= 20:
                recent_fp_rate = np.mean(list(self.false_positive_window)[-20:])
                target_fp_rate = self.adaptive_config.get('false_positive_threshold', 0.1)
                
                # Adjust threat threshold
                if recent_fp_rate > target_fp_rate * 1.5:  # Too many false positives
                    adjustment = min(0.05, (recent_fp_rate - target_fp_rate) * 0.2)
                    self.current_threat_threshold = min(0.9, self.base_threat_threshold + adjustment)
                    logger.debug(f"Enhanced adaptive: increased threat threshold to {self.current_threat_threshold:.3f} "
                               f"(FP rate: {recent_fp_rate:.3f})")
                    
                elif recent_fp_rate < target_fp_rate * 0.5:  # Very few false positives
                    adjustment = min(0.03, (target_fp_rate - recent_fp_rate) * 0.15)
                    self.current_threat_threshold = max(0.3, self.base_threat_threshold - adjustment)
                    logger.debug(f"Enhanced adaptive: decreased threat threshold to {self.current_threat_threshold:.3f} "
                               f"(FP rate: {recent_fp_rate:.3f})")
            
            # Adjust block threshold based on threat detection accuracy
            if len(self.detection_accuracy_window) >= 10:
                recent_accuracy = np.mean(list(self.detection_accuracy_window)[-10:])
                
                if recent_accuracy > 0.8:  # High accuracy, can be more aggressive
                    self.current_block_threshold = max(0.5, self.current_threat_threshold + 0.05)
                elif recent_accuracy < 0.6:  # Low accuracy, be more conservative
                    self.current_block_threshold = min(0.9, self.current_threat_threshold + 0.2)
                else:
                    self.current_block_threshold = self.current_threat_threshold + 0.1
            
        except Exception as e:
            logger.error(f"Adaptive threshold adjustment error: {e}")
    
    def add_whitelist_ip(self, ip_address):
        """Enhanced whitelist management"""
        try:
            with self.lock:
                self.whitelist_ips.add(ip_address)
                # Remove from blocked list if present
                self.blocked_ips.discard(ip_address)
                # Update IP statistics
                if ip_address in self.ip_statistics:
                    self.ip_statistics[ip_address]['threat_score'] = 0.0
                logger.info(f"Enhanced whitelist: added {ip_address}")
                return True
        except Exception as e:
            logger.error(f"Enhanced whitelist addition error: {e}")
            return False
    
    def remove_blocked_ip(self, ip_address):
        """Enhanced blocked IP removal"""
        try:
            with self.lock:
                if ip_address in self.blocked_ips:
                    self.blocked_ips.remove(ip_address)
                    # Reset threat score but keep statistics
                    if ip_address in self.ip_statistics:
                        self.ip_statistics[ip_address]['threat_score'] *= 0.5  # Reduce but don't eliminate
                    logger.info(f"Enhanced unblock: removed {ip_address}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Enhanced blocked IP removal error: {e}")
            return False
    
    def get_firewall_stats(self):
        """Get comprehensive enhanced firewall statistics"""
        try:
            with self.lock:
                # Calculate derived metrics
                total_decisions = (self.stats['true_positives'] + self.stats['false_positives'] + 
                                 self.stats['true_negatives'] + self.stats['false_negatives'])
                
                precision = (self.stats['true_positives'] / 
                           max(self.stats['true_positives'] + self.stats['false_positives'], 1))
                recall = (self.stats['true_positives'] / 
                         max(self.stats['true_positives'] + self.stats['false_negatives'], 1))
                accuracy = ((self.stats['true_positives'] + self.stats['true_negatives']) / 
                           max(total_decisions, 1))
                f1_score = (2 * precision * recall / max(precision + recall, 0.001))
                
                # Recent performance
                recent_fp_rate = (np.mean(list(self.false_positive_window)) 
                                if self.false_positive_window else 0.0)
                recent_accuracy = (np.mean(list(self.detection_accuracy_window)) 
                                 if self.detection_accuracy_window else 0.0)
                
                return {
                    **self.stats.copy(),
                    'blocked_ips_count': len(self.blocked_ips),
                    'whitelist_count': len(self.whitelist_ips),
                    'blocked_ports_count': len(self.blocked_ports),
                    'blocking_enabled': self.enable_blocking,
                    'adaptive_thresholds': {
                        'current_threat_threshold': self.current_threat_threshold,
                        'current_block_threshold': self.current_block_threshold,
                        'base_threat_threshold': self.base_threat_threshold,
                        'base_block_threshold': self.base_block_threshold
                    },
                    'performance_metrics': {
                        'precision': precision,
                        'recall': recall,
                        'accuracy': accuracy,
                        'f1_score': f1_score,
                        'recent_false_positive_rate': recent_fp_rate,
                        'recent_detection_accuracy': recent_accuracy
                    },
                    'ip_statistics_count': len(self.ip_statistics),
                    'threat_history_size': len(self.threat_history)
                }
        except Exception as e:
            logger.error(f"Enhanced firewall stats error: {e}")
            return {
                'packets_analyzed': self.stats.get('packets_analyzed', 0),
                'threats_detected': self.stats.get('threats_detected', 0),
                'packets_blocked': self.stats.get('packets_blocked', 0),
                'false_positives': 0, 'blocked_ips_count': 0, 'whitelist_count': 0,
                'blocked_ports_count': 0, 'blocking_enabled': False,
                'error': str(e)
            }
    
    def get_blocked_ips(self):
        """Get enhanced list of blocked IPs with statistics"""
        try:
            with self.lock:
                blocked_info = []
                for ip in self.blocked_ips:
                    if ip in self.ip_statistics:
                        stats = self.ip_statistics[ip]
                        blocked_info.append({
                            'ip': ip,
                            'packets': stats['packets'],
                            'threats': stats['threats'],
                            'threat_score': stats['threat_score'],
                            'last_seen': stats['last_seen'],
                            'blocked_count': stats['blocked']
                        })
                    else:
                        blocked_info.append({
                            'ip': ip,
                            'packets': 0, 'threats': 0, 'threat_score': 0.0,
                            'last_seen': time.time(), 'blocked_count': 0
                        })
                
                return blocked_info
        except Exception as e:
            logger.error(f"Enhanced blocked IPs retrieval error: {e}")
            return []
    
    def get_threat_summary(self):
        """Get threat detection summary and trends"""
        try:
            with self.lock:
                if not self.threat_history:
                    return {'total_threats': 0, 'recent_trend': 'stable'}
                
                recent_threats = list(self.threat_history)[-100:]
                current_time = time.time()
                
                # Time-based analysis
                hour_ago = current_time - 3600
                recent_hour_threats = [t for t in recent_threats if t['timestamp'] > hour_ago]
                
                # Threat score trends
                if len(recent_threats) >= 20:
                    recent_scores = [t['threat_score'] for t in recent_threats[-20:]]
                    older_scores = [t['threat_score'] for t in recent_threats[-40:-20]] if len(recent_threats) >= 40 else []
                    
                    if older_scores:
                        recent_avg = np.mean(recent_scores)
                        older_avg = np.mean(older_scores)
                        
                        if recent_avg > older_avg + 0.1:
                            trend = 'increasing'
                        elif recent_avg < older_avg - 0.1:
                            trend = 'decreasing'
                        else:
                            trend = 'stable'
                    else:
                        trend = 'insufficient_data'
                else:
                    trend = 'insufficient_data'
                
                return {
                    'total_threats': len(self.threat_history),
                    'recent_hour_threats': len(recent_hour_threats),
                    'recent_trend': trend,
                    'average_threat_score': np.mean([t['threat_score'] for t in recent_threats]),
                    'max_threat_score': max([t['threat_score'] for t in recent_threats]),
                    'blocked_actions': len([t for t in recent_threats if t['action'] == 'block'])
                }
                
        except Exception as e:
            logger.error(f"Threat summary error: {e}")
            return {'total_threats': 0, 'recent_trend': 'unknown', 'error': str(e)}
    
    def reset_stats(self):
        """Enhanced statistics reset with preservation of important data"""
        try:
            with self.lock:
                # Reset counters but preserve learning data
                old_stats = self.stats.copy()
                
                self.stats = {
                    'packets_analyzed': 0, 'threats_detected': 0, 'packets_blocked': 0,
                    'false_positives': 0, 'true_positives': 0, 'false_negatives': 0, 'true_negatives': 0
                }
                
                # Keep recent threat history and IP statistics for learning
                if len(self.threat_history) > 200:
                    self.threat_history = deque(list(self.threat_history)[-100:], maxlen=1000)
                
                # Reset old IP statistics but keep recent ones
                current_time = time.time()
                active_ips = {ip: stats for ip, stats in self.ip_statistics.items() 
                            if current_time - stats['last_seen'] < 3600}  # Keep last hour
                self.ip_statistics = defaultdict(lambda: {
                    'packets': 0, 'threats': 0, 'blocked': 0, 
                    'last_seen': time.time(), 'threat_score': 0.0
                }, active_ips)
                
                logger.info(f"Enhanced firewall statistics reset. Previous stats: {old_stats}")
                
        except Exception as e:
            logger.error(f"Enhanced firewall stats reset error: {e}")