import asyncio
import logging
import time
import subprocess
import signal
import sys
import json
import numpy as np
from pathlib import Path
from datetime import datetime

# Import with error handling
try:
    from mininet.net import Mininet
    from mininet.topo import Topo
    from mininet.node import Controller, OVSKernelSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.error(f"Mininet import error: {e}")
    logger.error("Please install Mininet: sudo apt-get install mininet")
    raise

try:
    from federated.simple_client import SimpleFederatedClient
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.error(f"Federated client import error: {e}")
    raise

logger = logging.getLogger(__name__)

class SimpleTopology(Topo):
    """Enhanced simple star topology with optimized configuration"""
    
    def __init__(self, num_hosts=3):
        super(SimpleTopology, self).__init__()
        
        logger.info(f"Creating enhanced star topology with {num_hosts} hosts")
        
        # Add single switch with enhanced configuration
        switch = self.addSwitch('s1', 
                               cls=OVSKernelSwitch,
                               protocols='OpenFlow13',
                               failMode='standalone')
        
        # Add hosts with optimized network parameters
        for i in range(num_hosts):
            host_name = f'h{i+1}'
            host_ip = f'10.0.0.{i+1}'
            
            # Add host with enhanced configuration
            host = self.addHost(host_name, 
                               ip=f'{host_ip}/24',
                               mac=f'00:00:00:00:00:0{i+1}',
                               defaultRoute=None)  # Will set manually for better control
            
            # Add enhanced link with optimized parameters
            self.addLink(host, switch,
                        cls=TCLink,
                        bw=1000,       # 1 Gbps for better performance
                        delay='0.5ms', # Reduced delay
                        loss=0,        # No packet loss
                        max_queue_size=100)
            
            logger.debug(f"Added enhanced host {host_name} ({host_ip}) with optimized link")
        
        logger.info(f"Enhanced topology created: {num_hosts} hosts -> 1 switch")

class RobustNetworkManager:
    """ENHANCED network manager with superior performance and stability"""
    
    def __init__(self, config):
        self.config = config
        self.net = None
        self.clients = []
        self.is_running = False
        self.current_phase = "learning"
        self.phase_lock = asyncio.Lock()
        self.start_time = None
        self.phase_change_event = asyncio.Event()
        
        # Enhanced configuration
        self.max_connectivity_attempts = 5
        self.connectivity_timeout = 10
        
        # Enhanced phase management
        self.phase_history = []
        self.phase_performance_metrics = {}
        self.learning_start_time = None
        self.testing_start_time = None
        
        # Performance tracking
        self.system_metrics = {
            'total_packets_processed': 0,
            'total_threats_detected': 0,
            'average_accuracy': 0.0,
            'federated_rounds': 0,
            'hyperparameter_adjustments': 0
        }
        
        # Set Mininet logging
        setLogLevel('error')
        
        # Enhanced signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Enhanced network manager initialized with superior capabilities")
        
    def _signal_handler(self, signum, frame):
        """Enhanced signal handler with graceful shutdown"""
        logger.info(f"Received signal {signum}, initiating enhanced graceful shutdown...")
        if self.is_running:
            asyncio.create_task(self.stop_system())
    
    async def start_system(self):
        """Start the enhanced federated firewall system"""
        logger.info("=" * 70)
        logger.info("STARTING ENHANCED FEDERATED FIREWALL SYSTEM")
        logger.info("=" * 70)
        
        try:
            self.start_time = time.time()
            self.learning_start_time = time.time()
            
            # Enhanced startup sequence
            await self._enhanced_cleanup_environment()
            await self._create_enhanced_network()
            await self._configure_enhanced_network()
            await self._verify_enhanced_connectivity()
            await self._start_enhanced_federated_learning()
            await self._start_enhanced_system_management()
            
            self.is_running = True
            logger.info("ENHANCED SYSTEM FULLY OPERATIONAL")
            
        except Exception as e:
            logger.error(f"Enhanced system startup failed: {e}")
            await self.stop_system()
            raise
    
    async def stop_system(self):
        """Enhanced graceful system shutdown"""
        if not self.is_running:
            return
        
        logger.info("INITIATING ENHANCED SYSTEM SHUTDOWN")
        self.is_running = False
        
        try:
            # Enhanced client shutdown
            logger.info("Stopping enhanced federated clients...")
            if self.clients:
                stop_tasks = [client.stop() for client in self.clients]
                results = await asyncio.gather(*stop_tasks, return_exceptions=True)
                
                # Log any shutdown issues
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Client {i} shutdown error: {result}")
            
            self.clients.clear()
            
            # Enhanced network shutdown
            if self.net:
                logger.info("Stopping enhanced network...")
                try:
                    self.net.stop()
                    logger.info("Network stopped successfully")
                except Exception as e:
                    logger.error(f"Network stop error: {e}")
                self.net = None
            
            # Final enhanced cleanup
            await self._enhanced_cleanup_environment()
            
            # Save final system report
            await self._save_final_system_report()
            
        except Exception as e:
            logger.error(f"Enhanced shutdown error: {e}")
        
        logger.info("ENHANCED SYSTEM SHUTDOWN COMPLETE")
    
    async def _enhanced_cleanup_environment(self):
        """Enhanced comprehensive environment cleanup"""
        logger.info("Performing enhanced environment cleanup...")
        
        cleanup_commands = [
            ['sudo', 'mn', '-c'],
            ['sudo', 'pkill', '-9', '-f', 'controller'],
            ['sudo', 'pkill', '-9', '-f', 'ovs'],
            ['sudo', 'fuser', '-k', '6633/tcp'],
            ['sudo', 'fuser', '-k', '6634/tcp']
        ]
        
        for cmd in cleanup_commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                logger.debug(f"Enhanced cleanup command {' '.join(cmd)}: return code {result.returncode}")
            except subprocess.TimeoutExpired:
                logger.warning(f"Enhanced cleanup command timed out: {' '.join(cmd)}")
            except FileNotFoundError:
                logger.debug(f"Enhanced cleanup command not found: {' '.join(cmd)}")
            except Exception as e:
                logger.debug(f"Enhanced cleanup command error: {e}")
        
        # Additional cleanup
        await asyncio.sleep(3)
        logger.info("Enhanced environment cleanup completed")
    
    async def _create_enhanced_network(self):
        """Create enhanced Mininet network with superior configuration"""
        logger.info("Creating enhanced network topology...")
        
        try:
            # Create enhanced topology
            num_clients = self.config.get('mininet', {}).get('num_clients', 3)
            topo = SimpleTopology(num_clients)
            
            # Create enhanced network
            self.net = Mininet(
                topo=topo,
                switch=OVSKernelSwitch,
                controller=Controller,
                link=TCLink,
                autoSetMacs=True,
                autoStaticArp=True,
                waitConnected=True,
                cleanup=True
            )
            
            # Start the enhanced network
            logger.info("Starting enhanced Mininet network...")
            self.net.start()
            
            # Enhanced network stabilization
            await asyncio.sleep(5)
            
            logger.info("Enhanced network created and started successfully")
            
        except Exception as e:
            logger.error(f"Enhanced network creation failed: {e}")
            raise
    
    async def _configure_enhanced_network(self):
        """Enhanced network configuration with superior optimization"""
        logger.info("Configuring enhanced network...")
        
        try:
            # Enhanced switch configuration
            switch = self.net.get('s1')
            if switch:
                # Clear existing flows
                switch.cmd('ovs-ofctl del-flows s1')
                await asyncio.sleep(1)
                
                # Add enhanced flow rules for better performance
                switch.cmd('ovs-ofctl add-flow s1 priority=100,actions=normal')
                switch.cmd('ovs-ofctl set-config s1 miss-send-len=65535')
                
                logger.info("Enhanced switch configured with optimized flows")
            
            # Enhanced host configuration
            for i, host in enumerate(self.net.hosts):
                host_name = host.name
                host_ip = host.IP()
                
                logger.info(f"Configuring enhanced host {host_name} ({host_ip})")
                
                # Enhanced network interface configuration
                host.cmd('ip link set lo up')
                host.cmd(f'ip link set {host_name}-eth0 up')
                host.cmd(f'ip link set {host_name}-eth0 mtu 1500')
                
                # Enhanced network optimization
                host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null')
                host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null')
                host.cmd('sysctl -w net.core.rmem_max=16777216 2>/dev/null')
                host.cmd('sysctl -w net.core.wmem_max=16777216 2>/dev/null')
                
                # Enhanced ARP configuration for all hosts
                for j, other_host in enumerate(self.net.hosts):
                    if host != other_host:
                        other_ip = other_host.IP()
                        other_mac = other_host.MAC()
                        host.cmd(f'arp -s {other_ip} {other_mac}')
                        logger.debug(f"Enhanced ARP entry: {other_ip} -> {other_mac}")
                
                # Enhanced routing configuration
                host.cmd(f'ip route add default dev {host_name}-eth0')
                host.cmd(f'ip route add 10.0.0.0/24 dev {host_name}-eth0')
            
            logger.info("Enhanced network configuration completed successfully")
            
        except Exception as e:
            logger.error(f"Enhanced network configuration failed: {e}")
            raise
    
    async def _verify_enhanced_connectivity(self):
        """Enhanced connectivity verification with detailed diagnostics"""
        logger.info("Verifying enhanced network connectivity...")
        
        for attempt in range(1, self.max_connectivity_attempts + 1):
            logger.info(f"Enhanced connectivity test {attempt}/{self.max_connectivity_attempts}")
            
            try:
                # Enhanced ping test with detailed analysis
                logger.info("Running enhanced pingall test...")
                result = self.net.pingAll(timeout='3')
                
                if result == 0.0:
                    logger.info("PERFECT ENHANCED CONNECTIVITY: 0% packet loss")
                    await self._verify_network_performance()
                    return True
                elif result <= 5.0:
                    logger.info(f"EXCELLENT ENHANCED CONNECTIVITY: {result}% packet loss")
                    await self._verify_network_performance()
                    return True
                elif result <= 15.0:
                    logger.warning(f"ACCEPTABLE ENHANCED CONNECTIVITY: {result}% packet loss")
                    if attempt == self.max_connectivity_attempts:
                        return True
                else:
                    logger.warning(f"POOR ENHANCED CONNECTIVITY: {result}% packet loss")
                
                # Enhanced connectivity repair if needed
                if attempt < self.max_connectivity_attempts:
                    await self._repair_enhanced_connectivity()
                    await asyncio.sleep(3)
                
            except Exception as e:
                logger.error(f"Enhanced connectivity test {attempt} failed: {e}")
                if attempt < self.max_connectivity_attempts:
                    await asyncio.sleep(3)
        
        # Accept connectivity and proceed
        logger.warning("Proceeding with current enhanced connectivity level")
        return True
    
    async def _verify_network_performance(self):
        """Verify network performance characteristics"""
        try:
            logger.info("Verifying enhanced network performance...")
            
            # Test bandwidth between hosts
            hosts = self.net.hosts
            if len(hosts) >= 2:
                h1, h2 = hosts[0], hosts[1]
                
                # Quick iperf test for bandwidth verification
                server = h2.popen('iperf -s -p 5001 -t 5', shell=True)
                await asyncio.sleep(1)
                
                client_result = h1.cmd('iperf -c %s -p 5001 -t 3 -f m' % h2.IP())
                server.terminate()
                
                if "Mbits/sec" in client_result:
                    logger.info("Enhanced network performance verified")
                else:
                    logger.warning("Enhanced network performance test inconclusive")
            
        except Exception as e:
            logger.debug(f"Enhanced network performance verification error: {e}")
    
    async def _repair_enhanced_connectivity(self):
        """Enhanced connectivity repair with advanced diagnostics"""
        logger.info("Performing enhanced connectivity repair...")
        
        try:
            # Enhanced switch repair
            switch = self.net.get('s1')
            if switch:
                switch.cmd('ovs-ofctl del-flows s1')
                await asyncio.sleep(1)
                switch.cmd('ovs-ofctl add-flow s1 priority=100,actions=normal')
                switch.cmd('ovs-ofctl add-flow s1 priority=50,dl_type=0x0806,actions=flood')  # ARP
                logger.debug("Enhanced switch flows repaired")
            
            # Enhanced ARP table refresh
            for host in self.net.hosts:
                try:
                    host.cmd('ip neigh flush all')
                    host.cmd('arp -d -a')
                    
                    # Re-establish ARP entries
                    for other_host in self.net.hosts:
                        if host != other_host:
                            other_ip = other_host.IP()
                            other_mac = other_host.MAC()
                            host.cmd(f'arp -s {other_ip} {other_mac}')
                            
                except Exception as e:
                    logger.debug(f"Enhanced ARP repair error for {host.name}: {e}")
            
            # Enhanced interface restart
            for host in self.net.hosts:
                try:
                    host.cmd(f'ip link set {host.name}-eth0 down')
                    await asyncio.sleep(0.5)
                    host.cmd(f'ip link set {host.name}-eth0 up')
                except Exception as e:
                    logger.debug(f"Enhanced interface restart error for {host.name}: {e}")
            
            logger.info("Enhanced connectivity repair completed")
            
        except Exception as e:
            logger.error(f"Enhanced connectivity repair error: {e}")
    
    async def _start_enhanced_federated_learning(self):
        """Start enhanced federated learning system"""
        logger.info("Starting enhanced federated learning system...")
        
        hosts = self.net.hosts
        successful_clients = 0
        
        # Create enhanced clients with staggered startup
        for i, host in enumerate(hosts):
            try:
                logger.info(f"Creating enhanced federated client on {host.name} ({host.IP()})")
                
                client = SimpleFederatedClient(i, self.config, host)
                self.clients.append(client)
                
                # Start client as enhanced background task
                asyncio.create_task(client.start())
                successful_clients += 1
                
                logger.info(f"Successfully started enhanced client on {host.name}")
                
                # Staggered startup for stability
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Failed to start enhanced client on {host.name}: {e}")
        
        if successful_clients == 0:
            raise Exception("No enhanced federated clients started successfully")
        
        logger.info(f"Started {successful_clients} enhanced federated learning clients")
    
    async def _start_enhanced_system_management(self):
        """Start enhanced system management with superior capabilities"""
        logger.info("Starting enhanced system management...")
        
        # Enhanced management tasks
        management_tasks = [
            self._enhanced_phase_management_loop(),
            self._enhanced_federated_averaging_loop(),
            self._enhanced_system_monitoring_loop()
        ]
        
        for task in management_tasks:
            asyncio.create_task(task)
        
        logger.info("Enhanced system management tasks started successfully")
    
    async def _enhanced_phase_management_loop(self):
        """Enhanced phase management with superior synchronization"""
        logger.info("Starting enhanced phase management system")
        
        try:
            # Enhanced learning phase
            learning_rounds = self.config.get('phases', {}).get('learning_rounds', 8)
            learning_duration = self.config.get('phases', {}).get('learning_duration', 45)
            total_learning_time = learning_rounds * learning_duration
            
            async with self.phase_lock:
                self.current_phase = "learning"
                self.learning_start_time = time.time()
                self.phase_history.append(("learning", time.time()))
            
            logger.info(f"ENHANCED LEARNING PHASE: {total_learning_time}s ({learning_rounds} rounds)")
            
            # Enhanced phase notification
            await self._notify_enhanced_phase_change("learning")
            
            # Enhanced learning phase monitoring
            learning_end_time = time.time() + total_learning_time
            monitoring_interval = 15
            
            while time.time() < learning_end_time and self.is_running:
                await asyncio.sleep(monitoring_interval)
                if not self.is_running:
                    return
                    
                # Monitor learning progress
                await self._monitor_learning_progress()
            
            # Enhanced transition to testing phase
            async with self.phase_lock:
                old_phase = self.current_phase
                self.current_phase = "testing"
                self.testing_start_time = time.time()
                self.phase_history.append(("testing", time.time()))
            
            logger.info("ENHANCED PHASE TRANSITION: Learning -> Testing")
            
            # Enhanced client synchronization
            await self._enhanced_client_synchronization()
            await self._notify_enhanced_phase_change("testing")
            
            # Enhanced testing phase
            testing_rounds = self.config.get('phases', {}).get('testing_rounds', 4)
            testing_duration = self.config.get('phases', {}).get('testing_duration', 30)
            total_testing_time = testing_rounds * testing_duration
            
            logger.info(f"ENHANCED TESTING PHASE: {total_testing_time}s ({testing_rounds} rounds)")
            
            # Enhanced testing phase monitoring
            testing_end_time = time.time() + total_testing_time
            
            while time.time() < testing_end_time and self.is_running:
                await asyncio.sleep(monitoring_interval)
                if not self.is_running:
                    return
                    
                # Monitor testing progress
                await self._monitor_testing_progress()
            
            # Enhanced final evaluation
            await self._perform_enhanced_final_evaluation()
            
            logger.info("ALL ENHANCED PHASES COMPLETED SUCCESSFULLY")
            
        except Exception as e:
            logger.error(f"Enhanced phase management error: {e}")
    
    async def _enhanced_client_synchronization(self):
        """Enhanced client synchronization with superior coordination"""
        try:
            logger.info("Performing enhanced client synchronization...")
            
            # Enhanced pre-synchronization
            await asyncio.sleep(5)
            
            # Enhanced federated averaging before phase change
            await self._perform_enhanced_federated_averaging()
            
            # Enhanced synchronization wait
            await asyncio.sleep(3)
            
            logger.info("Enhanced client synchronization completed")
            
        except Exception as e:
            logger.error(f"Enhanced client synchronization error: {e}")
    
    async def _notify_enhanced_phase_change(self, new_phase):
        """Enhanced phase change notification with superior coordination"""
        try:
            logger.info(f"Notifying {len(self.clients)} clients about enhanced phase change to {new_phase}")
            
            # Enhanced notification tasks
            notification_tasks = []
            for client in self.clients:
                try:
                    if hasattr(client, 'on_phase_change'):
                        notification_tasks.append(client.on_phase_change(new_phase))
                    else:
                        client.update_phase(new_phase)
                except Exception as e:
                    logger.error(f"Enhanced phase notification error for client {getattr(client, 'host_name', 'unknown')}: {e}")
            
            # Enhanced notification completion
            if notification_tasks:
                results = await asyncio.gather(*notification_tasks, return_exceptions=True)
                
                # Log any notification issues
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Enhanced notification task {i} failed: {result}")
            
            self.phase_change_event.set()
            logger.info(f"Enhanced phase change notification completed for {new_phase}")
            
        except Exception as e:
            logger.error(f"Enhanced phase change notification error: {e}")
    
    async def _monitor_learning_progress(self):
        """Monitor learning phase progress"""
        try:
            # Collect learning metrics
            total_accuracy = 0.0
            total_packets = 0
            total_threats = 0
            active_clients = 0
            
            for client in self.clients:
                try:
                    stats = client.get_training_stats()
                    if 'performance_metrics' in stats:
                        total_accuracy += stats['performance_metrics']['model_accuracy']
                        total_packets += stats['performance_metrics']['packets_processed']
                        total_threats += stats['performance_metrics']['threats_detected']
                        active_clients += 1
                except Exception as e:
                    logger.debug(f"Learning progress monitoring error for client: {e}")
            
            if active_clients > 0:
                avg_accuracy = total_accuracy / active_clients
                threat_rate = total_threats / max(total_packets, 1)
                
                self.system_metrics.update({
                    'average_accuracy': avg_accuracy,
                    'total_packets_processed': total_packets,
                    'total_threats_detected': total_threats
                })
                
                logger.info(f"Enhanced Learning Progress: Accuracy={avg_accuracy:.3f}, "
                          f"Packets={total_packets}, Threats={total_threats}, Rate={threat_rate:.3f}")
            
        except Exception as e:
            logger.error(f"Learning progress monitoring error: {e}")
    
    async def _monitor_testing_progress(self):
        """Monitor testing phase progress"""
        try:
            # Collect testing metrics
            total_test_accuracy = 0.0
            total_test_packets = 0
            active_test_clients = 0
            
            for client in self.clients:
                try:
                    stats = client.get_training_stats()
                    if stats.get('current_phase') == 'testing':
                        total_test_accuracy += stats.get('performance_metrics', {}).get('model_accuracy', 0)
                        total_test_packets += stats.get('data_stats', {}).get('test_samples', 0)
                        active_test_clients += 1
                except Exception as e:
                    logger.debug(f"Testing progress monitoring error for client: {e}")
            
            if active_test_clients > 0:
                avg_test_accuracy = total_test_accuracy / active_test_clients
                
                logger.info(f"Enhanced Testing Progress: Test Accuracy={avg_test_accuracy:.3f}, "
                          f"Test Packets={total_test_packets}, Active Clients={active_test_clients}")
            
        except Exception as e:
            logger.error(f"Testing progress monitoring error: {e}")
    
    async def _enhanced_federated_averaging_loop(self):
        """Enhanced federated averaging with superior algorithms"""
        try:
            averaging_interval = self.config.get('federated', {}).get('aggregation_interval', 20)
            
            while self.is_running:
                await asyncio.sleep(averaging_interval)
                
                if len(self.clients) > 1:
                    await self._perform_enhanced_federated_averaging()
                    
        except Exception as e:
            logger.error(f"Enhanced federated averaging loop error: {e}")
    
    async def _perform_enhanced_federated_averaging(self):
        """Enhanced federated averaging with superior weight aggregation"""
        try:
            logger.info("Performing enhanced federated averaging...")
            
            # Collect enhanced weights and metadata
            client_weights = []
            client_metadata = []
            successful_clients = []
            
            for client in self.clients:
                try:
                    weights = client.get_model_weights()
                    stats = client.get_training_stats()
                    
                    if weights and stats.get('data_stats', {}).get('training_samples', 0) > 0:
                        client_weights.append(weights)
                        
                        # Enhanced metadata for weighted averaging
                        metadata = {
                            'samples': stats['data_stats']['training_samples'],
                            'accuracy': stats.get('performance_metrics', {}).get('model_accuracy', 0.5),
                            'loss': stats.get('performance_metrics', {}).get('model_loss', 1.0),
                            'host': stats.get('host', 'unknown')
                        }
                        client_metadata.append(metadata)
                        successful_clients.append(metadata['host'])
                        
                except Exception as e:
                    logger.error(f"Enhanced weight collection error from {getattr(client, 'host_name', 'unknown')}: {e}")
            
            if len(client_weights) < 2:
                logger.warning("Insufficient clients for enhanced federated averaging")
                return
            
            # Enhanced weighted averaging
            averaged_weights = self._enhanced_federated_average_weights(client_weights, client_metadata)
            
            if not averaged_weights:
                logger.error("Enhanced federated averaging failed")
                return
            
            # Enhanced weight distribution
            distribution_count = 0
            for client in self.clients:
                try:
                    client.set_model_weights(averaged_weights)
                    distribution_count += 1
                except Exception as e:
                    logger.error(f"Enhanced weight distribution error to {getattr(client, 'host_name', 'unknown')}: {e}")
            
            self.system_metrics['federated_rounds'] += 1
            
            logger.info(f"Enhanced federated averaging completed: "
                       f"{len(successful_clients)} contributors, "
                       f"{distribution_count} recipients, "
                       f"Round {self.system_metrics['federated_rounds']}")
            
        except Exception as e:
            logger.error(f"Enhanced federated averaging error: {e}")
    
    def _enhanced_federated_average_weights(self, weights_list, metadata_list):
        """Enhanced federated averaging algorithm with quality weighting"""
        try:
            import torch
            
            if not weights_list or not metadata_list:
                logger.error("Empty weights list or metadata for enhanced averaging")
                return {}
            
            # Enhanced weighting strategy
            total_weight = 0.0
            client_weights = []
            
            for metadata in metadata_list:
                # Multi-factor weighting
                sample_weight = metadata['samples']
                accuracy_weight = max(0.1, metadata['accuracy'])  # Minimum weight
                quality_weight = max(0.1, 1.0 / (1.0 + metadata['loss']))  # Inverse loss weighting
                
                # Combined weight
                combined_weight = (0.5 * sample_weight + 
                                 0.3 * accuracy_weight * 100 + 
                                 0.2 * quality_weight * 10)
                
                client_weights.append(combined_weight)
                total_weight += combined_weight
            
            if total_weight == 0:
                logger.error("Total weight is zero in enhanced averaging")
                return weights_list[0] if weights_list else {}
            
            # Normalize weights
            normalized_weights = [w / total_weight for w in client_weights]
            
            # Enhanced parameter averaging
            averaged_weights = {}
            param_names = list(weights_list[0].keys())
            
            for param_name in param_names:
                try:
                    weighted_params = []
                    
                    for i, client_weights_dict in enumerate(weights_list):
                        if param_name in client_weights_dict:
                            weighted_param = normalized_weights[i] * client_weights_dict[param_name]
                            weighted_params.append(weighted_param)
                    
                    if weighted_params:
                        averaged_weights[param_name] = torch.stack(weighted_params).sum(dim=0)
                    
                except Exception as e:
                    logger.error(f"Enhanced parameter averaging error for {param_name}: {e}")
                    continue
            
            logger.debug(f"Enhanced averaging weights: {[f'{w:.3f}' for w in normalized_weights]}")
            return averaged_weights
            
        except Exception as e:
            logger.error(f"Enhanced weight averaging error: {e}")
            return weights_list[0] if weights_list else {}
    
    async def _enhanced_system_monitoring_loop(self):
        """Enhanced system monitoring with comprehensive metrics"""
        try:
            monitoring_interval = 30
            
            while self.is_running:
                await asyncio.sleep(monitoring_interval)
                
                # Collect system metrics
                await self._collect_system_metrics()
                
                # Log system status
                await self._log_system_status()
                
        except Exception as e:
            logger.error(f"Enhanced system monitoring error: {e}")
    
    async def _collect_system_metrics(self):
        """Collect comprehensive system metrics"""
        try:
            total_clients = len(self.clients)
            active_clients = 0
            total_accuracy = 0.0
            total_packets = 0
            total_threats = 0
            
            for client in self.clients:
                try:
                    stats = client.get_training_stats()
                    if stats and 'performance_metrics' in stats:
                        active_clients += 1
                        total_accuracy += stats['performance_metrics'].get('model_accuracy', 0)
                        total_packets += stats['performance_metrics'].get('packets_processed', 0)
                        total_threats += stats['performance_metrics'].get('threats_detected', 0)
                except Exception as e:
                    logger.debug(f"Client stats collection error: {e}")
            
            if active_clients > 0:
                self.system_metrics.update({
                    'active_clients': active_clients,
                    'total_clients': total_clients,
                    'average_accuracy': total_accuracy / active_clients,
                    'total_packets_processed': total_packets,
                    'total_threats_detected': total_threats,
                    'threat_detection_rate': total_threats / max(total_packets, 1)
                })
            
        except Exception as e:
            logger.error(f"System metrics collection error: {e}")
    
    async def _log_system_status(self):
        """Log comprehensive system status"""
        try:
            uptime = time.time() - self.start_time if self.start_time else 0
            
            logger.info(f"ENHANCED SYSTEM STATUS [{self.current_phase.upper()}]:")
            logger.info(f"  Uptime: {uptime:.1f}s")
            logger.info(f"  Active Clients: {self.system_metrics.get('active_clients', 0)}/{self.system_metrics.get('total_clients', 0)}")
            logger.info(f"  Average Accuracy: {self.system_metrics.get('average_accuracy', 0):.3f}")
            logger.info(f"  Total Packets: {self.system_metrics.get('total_packets_processed', 0)}")
            logger.info(f"  Threats Detected: {self.system_metrics.get('total_threats_detected', 0)}")
            logger.info(f"  Federated Rounds: {self.system_metrics.get('federated_rounds', 0)}")
            
        except Exception as e:
            logger.error(f"System status logging error: {e}")
    
    async def _perform_enhanced_final_evaluation(self):
        """Perform enhanced final system evaluation"""
        try:
            logger.info("PERFORMING ENHANCED FINAL EVALUATION")
            
            # Collect final statistics from all clients
            final_stats = []
            confusion_matrix_data = {
                'true_positives': 0,
                'true_negatives': 0,
                'false_positives': 0,
                'false_negatives': 0
            }
            
            for client in self.clients:
                try:
                    stats = client.get_training_stats()
                    if stats:
                        final_stats.append(stats)
                        
                        # Aggregate confusion matrix data from client stats
                        client_metrics = stats.get('performance_metrics', {})
                        if 'confusion_matrix' in client_metrics:
                            cm = client_metrics['confusion_matrix']
                            confusion_matrix_data['true_positives'] += cm.get('true_positives', 0)
                            confusion_matrix_data['true_negatives'] += cm.get('true_negatives', 0)
                            confusion_matrix_data['false_positives'] += cm.get('false_positives', 0)
                            confusion_matrix_data['false_negatives'] += cm.get('false_negatives', 0)
                        
                except Exception as e:
                    logger.error(f"Final stats collection error: {e}")
            
            if final_stats:
                # Calculate aggregate metrics
                total_accuracy = sum(s.get('performance_metrics', {}).get('model_accuracy', 0) for s in final_stats)
                avg_accuracy = total_accuracy / len(final_stats)
                
                total_packets = sum(s.get('performance_metrics', {}).get('packets_processed', 0) for s in final_stats)
                total_threats = sum(s.get('performance_metrics', {}).get('threats_detected', 0) for s in final_stats)
                
                # Calculate confusion matrix metrics
                total_predictions = (confusion_matrix_data['true_positives'] + 
                                   confusion_matrix_data['true_negatives'] + 
                                   confusion_matrix_data['false_positives'] + 
                                   confusion_matrix_data['false_negatives'])
                
                if total_predictions > 0:
                    precision = confusion_matrix_data['true_positives'] / max(confusion_matrix_data['true_positives'] + confusion_matrix_data['false_positives'], 1)
                    recall = confusion_matrix_data['true_positives'] / max(confusion_matrix_data['true_positives'] + confusion_matrix_data['false_negatives'], 1)
                    f1_score = 2 * (precision * recall) / max(precision + recall, 1e-8)
                else:
                    precision = recall = f1_score = 0.0
                
                logger.info(f"FINAL EVALUATION RESULTS:")
                logger.info(f"  Participating Clients: {len(final_stats)}")
                logger.info(f"  Average Model Accuracy: {avg_accuracy:.3f}")
                logger.info(f"  Total Packets Processed: {total_packets}")
                logger.info(f"  Total Threats Detected: {total_threats}")
                logger.info(f"  Overall Threat Rate: {total_threats/max(total_packets,1):.3f}")
                logger.info(f"  Federated Learning Rounds: {self.system_metrics.get('federated_rounds', 0)}")
                
                # Log confusion matrix results
                logger.info(f"CONFUSION MATRIX RESULTS:")
                logger.info(f"  True Positives: {confusion_matrix_data['true_positives']}")
                logger.info(f"  True Negatives: {confusion_matrix_data['true_negatives']}")
                logger.info(f"  False Positives: {confusion_matrix_data['false_positives']}")
                logger.info(f"  False Negatives: {confusion_matrix_data['false_negatives']}")
                logger.info(f"  Precision: {precision:.3f}")
                logger.info(f"  Recall: {recall:.3f}")
                logger.info(f"  F1-Score: {f1_score:.3f}")
            
            # Save final evaluation report with confusion matrix
            await self._save_final_evaluation_report(final_stats, confusion_matrix_data)
            
        except Exception as e:
            logger.error(f"Enhanced final evaluation error: {e}")
    
    async def _save_final_evaluation_report(self, final_stats, confusion_matrix_data):
        """Save final evaluation report with confusion matrix"""
        try:
            reports_dir = Path("logs/reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = reports_dir / f"final_evaluation_{timestamp}.json"
            
            # Calculate additional confusion matrix metrics
            total_predictions = (confusion_matrix_data['true_positives'] + 
                               confusion_matrix_data['true_negatives'] + 
                               confusion_matrix_data['false_positives'] + 
                               confusion_matrix_data['false_negatives'])
            
            if total_predictions > 0:
                precision = confusion_matrix_data['true_positives'] / max(confusion_matrix_data['true_positives'] + confusion_matrix_data['false_positives'], 1)
                recall = confusion_matrix_data['true_positives'] / max(confusion_matrix_data['true_positives'] + confusion_matrix_data['false_negatives'], 1)
                f1_score = 2 * (precision * recall) / max(precision + recall, 1e-8)
                accuracy = (confusion_matrix_data['true_positives'] + confusion_matrix_data['true_negatives']) / total_predictions
            else:
                precision = recall = f1_score = accuracy = 0.0
            
            evaluation_report = {
                'timestamp': timestamp,
                'system_metrics': self.system_metrics,
                'phase_history': self.phase_history,
                'client_final_stats': final_stats,
                'total_uptime': time.time() - self.start_time if self.start_time else 0,
                'confusion_matrix': {
                    'raw_counts': confusion_matrix_data,
                    'metrics': {
                        'precision': precision,
                        'recall': recall,
                        'f1_score': f1_score,
                        'accuracy': accuracy,
                        'total_predictions': total_predictions
                    }
                }
            }
            
            with open(report_file, 'w') as f:
                json.dump(evaluation_report, f, indent=2, default=str)
            
            logger.info(f"Final evaluation report saved: {report_file}")
            logger.info("✅ Confusion matrix successfully updated in final result JSON file")
            
        except Exception as e:
            logger.error(f"Final evaluation report save error: {e}")
    
    async def _save_final_system_report(self):
        """Save final system report"""
        try:
            reports_dir = Path("logs/reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = reports_dir / f"system_shutdown_{timestamp}.json"
            
            shutdown_report = {
                'timestamp': timestamp,
                'total_uptime': time.time() - self.start_time if self.start_time else 0,
                'system_metrics': self.system_metrics,
                'phase_history': self.phase_history,
                'final_phase': self.current_phase,
                'clients_count': len(self.clients)
            }
            
            with open(report_file, 'w') as f:
                json.dump(shutdown_report, f, indent=2, default=str)
            
            logger.info(f"Final system report saved: {report_file}")
            
        except Exception as e:
            logger.debug(f"Final system report save error: {e}")
    
    def get_current_phase(self):
        """Get current enhanced system phase"""
        return self.current_phase
    
    def get_system_status(self):
        """Get enhanced comprehensive system status"""
        try:
            return {
                'is_running': self.is_running,
                'current_phase': self.current_phase,
                'num_clients': len(self.clients),
                'network_active': self.net is not None,
                'phase_history': self.phase_history,
                'system_metrics': self.system_metrics,
                'clients_status': [
                    {
                        'host_name': getattr(client, 'host_name', 'unknown'),
                        'host_ip': getattr(client, 'host_ip', 'unknown'),
                        'is_running': getattr(client, 'is_running', False),
                        'current_phase': getattr(client, 'current_phase', 'unknown'),
                        'training_round': getattr(client, 'training_round', 0)
                    }
                    for client in self.clients
                ],
                'uptime_seconds': time.time() - self.start_time if self.start_time else 0
            }
        except Exception as e:
            logger.error(f"Enhanced system status error: {e}")
            return {
                'is_running': self.is_running,
                'current_phase': self.current_phase,
                'num_clients': 0,
                'network_active': False,
                'clients_status': [],
                'system_metrics': {},
                'error': str(e)
            }