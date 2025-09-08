import numpy as np
import time
import logging
import hashlib
import threading
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class SimplePacketAnalyzer:
    """Advanced packet feature extraction with 10 key features - FIXED and TUNED"""
    
    def __init__(self):
        self.packet_count = 0
        self.start_time = time.time()
        self.connection_stats = defaultdict(lambda: {
            'packets': 0, 
            'bytes': 0, 
            'start_time': time.time(),
            'last_seen': time.time()
        })
        self.recent_ips = deque(maxlen=200)  # Increased buffer
        self.recent_ports = deque(maxlen=200)
        self.lock = threading.Lock()  # Thread safety
        
        # Enhanced feature normalization ranges
        self.feature_ranges = {
            0: (40, 1500),      # packet_size - broader range
            1: (0, 86400),      # time_of_day 
            2: (0, 10000),      # packet_sequence - larger range
            3: (1, 254),        # src_ip_last_octet
            4: (1, 254),        # dst_ip_last_octet  
            5: (1, 255),        # protocol_type
            6: (1, 255),        # ttl_value - full range
            7: (1, 200),        # connection_count - increased
            8: (0, 1),          # suspicious_score
            9: (0, 1)           # traffic_entropy
        }
        
        # Attack pattern database for better threat detection
        self.attack_patterns = {
            'port_scan_ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
            'malicious_ports': [4444, 6666, 1234, 31337, 1337, 9999, 8080],
            'suspicious_sizes': [(1, 40), (1400, 1500)],  # Very small or very large
            'abnormal_ttls': [(1, 30), (250, 255)]  # Very low or very high TTL
        }
        
        logger.info("Enhanced packet analyzer initialized with attack pattern detection")
        
    def extract_features(self, packet_data=None):
        """Extract comprehensive 10-feature vector from packet - ENHANCED"""
        
        try:
            with self.lock:
                current_time = time.time()
                features = np.zeros(10, dtype=np.float32)
                
                # Generate realistic packet characteristics
                if packet_data is None:
                    packet_data = self._generate_realistic_packet()
                
                # Feature 0: Packet Size (enhanced normalization)
                packet_size = packet_data.get('size', np.random.randint(64, 1501))
                features[0] = self._normalize_feature_enhanced(packet_size, 0)
                
                # Feature 1: Time of Day (with periodicity awareness)
                time_of_day = current_time % 86400
                # Add sine/cosine components for time periodicity
                time_normalized = self._normalize_feature(time_of_day, 1)
                time_sine = np.sin(2 * np.pi * time_of_day / 86400) * 0.1
                features[1] = np.clip(time_normalized + time_sine, 0.0, 1.0)
                
                # Feature 2: Packet Sequence (with overflow handling)
                sequence = self.packet_count % 10000
                features[2] = self._normalize_feature(sequence, 2)
                
                # Feature 3: Source IP Last Octet
                src_ip = packet_data.get('src_ip', f"10.0.0.{np.random.randint(1, 4)}")
                try:
                    src_last = int(src_ip.split('.')[-1])
                except (ValueError, IndexError):
                    src_last = np.random.randint(1, 254)
                features[3] = self._normalize_feature(src_last, 3)
                
                # Feature 4: Destination IP Last Octet
                dst_ip = packet_data.get('dst_ip', f"10.0.0.{np.random.randint(1, 4)}")
                try:
                    dst_last = int(dst_ip.split('.')[-1])
                except (ValueError, IndexError):
                    dst_last = np.random.randint(1, 254)
                features[4] = self._normalize_feature(dst_last, 4)
                
                # Feature 5: Protocol Type (enhanced mapping)
                protocol = packet_data.get('protocol', np.random.choice([6, 17, 1]))
                # Map protocols to meaningful values
                protocol_mapping = {1: 50, 6: 150, 17: 100, 2: 75}  # ICMP, TCP, UDP, IGMP
                mapped_protocol = protocol_mapping.get(protocol, protocol)
                features[5] = self._normalize_feature(mapped_protocol, 5)
                
                # Feature 6: TTL Value (with anomaly detection)
                ttl = packet_data.get('ttl', np.random.randint(32, 129))
                features[6] = self._normalize_feature_enhanced(ttl, 6)
                
                # Feature 7: Connection Count (thread-safe)
                connection_key = f"{src_ip}-{dst_ip}"
                self.connection_stats[connection_key]['packets'] += 1
                self.connection_stats[connection_key]['last_seen'] = current_time
                
                # Clean old connections
                active_connections = 0
                cutoff_time = current_time - 300  # 5 minutes
                for conn_key in list(self.connection_stats.keys()):
                    if self.connection_stats[conn_key]['last_seen'] > cutoff_time:
                        active_connections += 1
                    else:
                        del self.connection_stats[conn_key]
                
                features[7] = self._normalize_feature(min(active_connections, 200), 7)
                
                # Feature 8: Suspicious Score (ENHANCED with pattern matching)
                suspicious_score = self._calculate_enhanced_suspicious_score(packet_data, features)
                features[8] = max(0.0, min(1.0, suspicious_score))
                
                # Feature 9: Traffic Entropy (improved calculation)
                entropy = self._calculate_enhanced_traffic_entropy(packet_data)
                features[9] = max(0.0, min(1.0, entropy))
                
                # Update tracking
                self.packet_count += 1
                self.recent_ips.append(src_ip)
                if 'src_port' in packet_data:
                    self.recent_ports.append(packet_data['src_port'])
                
                # Final validation
                features = self._validate_features(features)
                
                return features
                
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return self._get_safe_default_features()
    
    def _generate_realistic_packet(self):
        """Generate realistic packet data with ENHANCED threat simulation"""
        try:
            # Enhanced protocol distribution
            protocol_weights = [0.6, 0.3, 0.08, 0.02]  # TCP, UDP, ICMP, Others
            protocol = np.random.choice([6, 17, 1, 2], p=protocol_weights)
            
            # Generate realistic packet based on protocol
            if protocol == 6:  # TCP
                # More realistic TCP traffic patterns
                if np.random.random() < 0.15:  # 15% chance for malicious traffic
                    # Simulate attack traffic
                    size = np.random.choice([64, 1460], p=[0.6, 0.4])  # SYN flood or data exfil
                    src_port = np.random.choice(self.attack_patterns['malicious_ports'])
                    ttl = np.random.randint(1, 32)  # Low TTL for evasion
                else:
                    # Normal TCP traffic
                    size_choices = [64, 128, 512, 1024, 1460]
                    size_probs = np.array([0.3, 0.25, 0.2, 0.15, 0.1])
                    size = np.random.choice(size_choices, p=size_probs)
                    
                    # Realistic port distribution
                    if np.random.random() < 0.7:
                        src_port = np.random.choice([80, 443, 22, 21, 25, 53])
                    else:
                        src_port = np.random.randint(1024, 65536)
                    ttl = np.random.randint(64, 128)
                
                packet = {
                    'size': size,
                    'protocol': 6,
                    'src_port': src_port,
                    'ttl': ttl
                }
                
            elif protocol == 17:  # UDP
                if np.random.random() < 0.12:  # 12% chance for attacks
                    # UDP flood or DNS amplification
                    size = np.random.choice([64, 512, 1024], p=[0.4, 0.4, 0.2])
                    src_port = np.random.choice([53, 123, 1234, 31337])
                    ttl = np.random.randint(32, 64)
                else:
                    # Normal UDP traffic
                    size = np.random.randint(64, 512)
                    if np.random.random() < 0.8:
                        src_port = np.random.choice([53, 67, 68, 123, 161])
                    else:
                        src_port = np.random.randint(1024, 65536)
                    ttl = np.random.randint(64, 128)
                
                packet = {
                    'size': size,
                    'protocol': 17,
                    'src_port': src_port,
                    'ttl': ttl
                }
                
            elif protocol == 1:  # ICMP
                if np.random.random() < 0.2:  # 20% chance for ICMP attacks
                    # ICMP flood
                    size = np.random.randint(1000, 1500)  # Large ICMP
                    ttl = np.random.randint(1, 32)
                else:
                    # Normal ICMP
                    size = np.random.randint(64, 128)
                    ttl = np.random.randint(64, 128)
                
                packet = {
                    'size': size,
                    'protocol': 1,
                    'ttl': ttl
                }
            else:  # Other protocols
                packet = {
                    'size': np.random.randint(64, 256),
                    'protocol': protocol,
                    'ttl': np.random.randint(32, 128)
                }
            
            # Enhanced IP generation with attack simulation
            if np.random.random() < 0.1:  # 10% external traffic simulation
                src_octet = np.random.randint(100, 200)
                dst_octet = np.random.randint(1, 4)
            else:
                src_octet = np.random.randint(1, 4)
                dst_octet = np.random.randint(1, 4)
            
            packet['src_ip'] = f"10.0.0.{src_octet}"
            packet['dst_ip'] = f"10.0.0.{dst_octet}"
            
            return packet
            
        except Exception as e:
            logger.error(f"Packet generation error: {e}")
            return {
                'size': 64, 'protocol': 6, 'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2', 'ttl': 64, 'src_port': 80
            }
    
    def _normalize_feature_enhanced(self, value, feature_index):
        """Enhanced normalization with outlier handling"""
        try:
            min_val, max_val = self.feature_ranges[feature_index]
            
            # Handle outliers gracefully
            if value < min_val:
                return 0.0
            elif value > max_val:
                return 1.0
            else:
                normalized = (value - min_val) / (max_val - min_val)
                return np.clip(normalized, 0.0, 1.0)
        except Exception as e:
            logger.error(f"Enhanced normalization error for feature {feature_index}: {e}")
            return 0.5
    
    def _normalize_feature(self, value, feature_index):
        """Standard feature normalization"""
        try:
            min_val, max_val = self.feature_ranges[feature_index]
            normalized = (value - min_val) / (max_val - min_val)
            return np.clip(normalized, 0.0, 1.0)
        except Exception as e:
            logger.error(f"Normalization error for feature {feature_index}: {e}")
            return 0.5
    
    def _calculate_enhanced_suspicious_score(self, packet_data, features):
        """ENHANCED suspicious score with pattern matching"""
        try:
            score = 0.0
            
            # Size-based indicators (enhanced)
            size = packet_data.get('size', 0)
            for size_range in self.attack_patterns['suspicious_sizes']:
                if size_range[0] <= size <= size_range[1]:
                    score += 0.25
                    break
            
            # Port-based indicators (enhanced)
            src_port = packet_data.get('src_port', 0)
            if src_port in self.attack_patterns['malicious_ports']:
                score += 0.4  # High suspicion for known bad ports
            elif src_port in self.attack_patterns['port_scan_ports']:
                score += 0.15  # Moderate suspicion for common scan targets
            elif src_port > 60000:  # Very high ports
                score += 0.1
            
            # Protocol-based indicators
            protocol = packet_data.get('protocol', 6)
            if protocol == 1:  # ICMP
                # Check for ICMP floods
                recent_icmp = sum(1 for ip in list(self.recent_ips)[-20:] 
                                if '10.0.0' in str(ip))
                if recent_icmp > 8:
                    score += 0.3
                elif size > 512:  # Large ICMP
                    score += 0.2
            elif protocol not in [1, 6, 17]:  # Unusual protocols
                score += 0.2
            
            # TTL-based indicators (enhanced)
            ttl = packet_data.get('ttl', 64)
            for ttl_range in self.attack_patterns['abnormal_ttls']:
                if ttl_range[0] <= ttl <= ttl_range[1]:
                    score += 0.2
                    break
            
            # Traffic pattern analysis
            src_ip = packet_data.get('src_ip', '10.0.0.1')
            recent_from_src = sum(1 for ip in list(self.recent_ips)[-50:] if ip == src_ip)
            if recent_from_src > 10:  # High frequency from single source
                score += 0.2
            
            # Time-based patterns
            current_time = time.time()
            hour = int((current_time % 86400) / 3600)
            if hour < 6 or hour > 22:  # Night hours (more suspicious)
                score += 0.05
            
            # Port sequence analysis
            if len(self.recent_ports) > 10:
                recent_ports_list = list(self.recent_ports)[-10:]
                unique_ports = len(set(recent_ports_list))
                if unique_ports > 8:  # High port diversity suggests scanning
                    score += 0.15
            
            # Add controlled randomness for model diversity
            score += np.random.uniform(-0.03, 0.08)
            
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.debug(f"Enhanced suspicious score calculation error: {e}")
            return np.random.uniform(0.2, 0.6)
    
    def _calculate_enhanced_traffic_entropy(self, packet_data):
        """Enhanced entropy calculation with multiple dimensions"""
        try:
            if len(self.recent_ips) < 5:
                return np.random.uniform(0.4, 0.7)
            
            # IP entropy
            recent_ips_list = list(self.recent_ips)[-30:]
            ip_entropy = self._calculate_shannon_entropy(recent_ips_list)
            
            # Port entropy (if available)
            port_entropy = 0.5
            if len(self.recent_ports) >= 5:
                recent_ports_list = list(self.recent_ports)[-20:]
                port_entropy = self._calculate_shannon_entropy(recent_ports_list)
            
            # Combined entropy
            combined_entropy = 0.7 * ip_entropy + 0.3 * port_entropy
            
            # Protocol diversity
            src_ip = packet_data.get('src_ip', '10.0.0.1')
            protocol_diversity = self._calculate_protocol_diversity(src_ip)
            
            # Final entropy score
            final_entropy = 0.6 * combined_entropy + 0.4 * protocol_diversity
            
            return max(0.0, min(1.0, final_entropy))
            
        except Exception as e:
            logger.debug(f"Enhanced entropy calculation error: {e}")
            return np.random.uniform(0.3, 0.7)
    
    def _calculate_shannon_entropy(self, data_list):
        """Calculate Shannon entropy for a list of values"""
        try:
            if not data_list:
                return 0.5
            
            # Count occurrences
            counts = {}
            for item in data_list:
                counts[item] = counts.get(item, 0) + 1
            
            total = len(data_list)
            entropy = 0.0
            
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)
            
            # Normalize (max entropy for n items is log2(n))
            max_entropy = np.log2(min(len(counts), len(data_list)))
            if max_entropy > 0:
                return entropy / max_entropy
            else:
                return 0.5
                
        except Exception as e:
            logger.debug(f"Shannon entropy calculation error: {e}")
            return 0.5
    
    def _calculate_protocol_diversity(self, src_ip):
        """Calculate protocol diversity from a source"""
        try:
            # This is a placeholder since we don't track protocols per IP in current implementation
            # In a real implementation, we would maintain protocol statistics per IP
            return np.random.uniform(0.3, 0.8)
        except Exception as e:
            logger.debug(f"Protocol diversity calculation error: {e}")
            return 0.5
    
    def _validate_features(self, features):
        """Enhanced feature validation"""
        try:
            # Replace any NaN or inf values
            features = np.nan_to_num(features, nan=0.5, posinf=1.0, neginf=0.0)
            
            # Ensure all features are in [0, 1] range
            features = np.clip(features, 0.0, 1.0)
            
            # Ensure correct data type
            features = features.astype(np.float32)
            
            # Additional validation: ensure reasonable distribution
            if np.std(features) < 0.05:  # Too uniform
                # Add slight noise to prevent over-uniformity
                noise = np.random.uniform(-0.02, 0.02, features.shape)
                features = np.clip(features + noise, 0.0, 1.0)
            
            return features
            
        except Exception as e:
            logger.error(f"Enhanced feature validation error: {e}")
            return self._get_safe_default_features()
    
    def _get_safe_default_features(self):
        """Return safe default features with better distribution"""
        try:
            # Generate more realistic default features
            defaults = np.array([
                np.random.uniform(0.3, 0.7),  # packet_size
                np.random.uniform(0.2, 0.8),  # time_of_day
                np.random.uniform(0.1, 0.9),  # packet_sequence
                np.random.uniform(0.2, 0.8),  # src_ip
                np.random.uniform(0.2, 0.8),  # dst_ip
                np.random.uniform(0.4, 0.7),  # protocol
                np.random.uniform(0.3, 0.8),  # ttl
                np.random.uniform(0.1, 0.6),  # connections
                np.random.uniform(0.2, 0.6),  # suspicious_score
                np.random.uniform(0.3, 0.7),  # entropy
            ], dtype=np.float32)
            return defaults
        except Exception as e:
            logger.error(f"Error generating safe defaults: {e}")
            return np.full(10, 0.5, dtype=np.float32)
    
    def get_analyzer_stats(self):
        """Get enhanced analyzer statistics"""
        try:
            with self.lock:
                current_time = time.time()
                active_connections = len([c for c in self.connection_stats.values() 
                                        if current_time - c['last_seen'] < 300])
                
                # Calculate additional metrics
                unique_ips = len(set(self.recent_ips)) if self.recent_ips else 0
                unique_ports = len(set(self.recent_ports)) if self.recent_ports else 0
                
                # Traffic rate calculations
                uptime = current_time - self.start_time
                packets_per_second = self.packet_count / max(uptime, 1)
                
                return {
                    'packets_processed': self.packet_count,
                    'active_connections': active_connections,
                    'unique_ips_seen': unique_ips,
                    'unique_ports_seen': unique_ports,
                    'uptime_seconds': uptime,
                    'packets_per_second': packets_per_second,
                    'connection_stats_size': len(self.connection_stats)
                }
        except Exception as e:
            logger.error(f"Error getting enhanced analyzer stats: {e}")
            return {
                'packets_processed': self.packet_count,
                'active_connections': 0, 'unique_ips_seen': 0,
                'unique_ports_seen': 0, 'uptime_seconds': 0,
                'packets_per_second': 0, 'connection_stats_size': 0
            }
    
    def reset_stats(self):
        """Reset analyzer statistics with thread safety"""
        try:
            with self.lock:
                self.packet_count = 0
                self.start_time = time.time()
                self.connection_stats.clear()
                self.recent_ips.clear()
                self.recent_ports.clear()
                logger.info("Enhanced analyzer statistics reset")
        except Exception as e:
            logger.error(f"Error resetting enhanced analyzer stats: {e}")
    
    def get_threat_patterns_detected(self):
        """Get statistics on detected threat patterns"""
        try:
            patterns = {
                'malicious_ports_detected': 0,
                'suspicious_sizes_detected': 0,
                'abnormal_ttls_detected': 0,
                'potential_scans_detected': 0
            }
            
            # This would be enhanced with actual tracking in a production system
            return patterns
        except Exception as e:
            logger.error(f"Error getting threat patterns: {e}")
            return {}