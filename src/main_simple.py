import os
import sys
import asyncio
import yaml
import logging
import time
import argparse
import traceback
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

# Enhanced imports with comprehensive error handling
try:
    from mininet_controller.simple_network import RobustNetworkManager
    from utils.logging_utils import setup_logging
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR: {e}")
    print("Please ensure all required modules are installed and the project structure is correct.")
    print("Run setup script: sudo env \"PATH=$PATH\" python3 scripts/setup_system.py")
    sys.exit(1)

def check_enhanced_environment():
    """Enhanced comprehensive environment check"""
    
    print("Performing enhanced environment validation...")
    
    # Enhanced root privileges check
    if os.geteuid() != 0:
        print("🚫 ROOT PRIVILEGES REQUIRED")
        print("This enhanced script requires root access for Mininet operations.")
        print(f"Please run: sudo env \"PATH=$PATH\" python3 {' '.join(sys.argv)}")
        print("Environment preservation is critical for proper operation.")
        return False
    
    # Enhanced Python version check
    if sys.version_info < (3, 7):
        print(f"🚫 Python 3.7+ required (Current: {sys.version})")
        return False
    
    # Enhanced module availability check
    required_modules = [
        ('torch', 'PyTorch - Deep Learning Framework'),
        ('numpy', 'NumPy - Numerical Computing'), 
        ('yaml', 'PyYAML - Configuration Parser'),
        ('mininet', 'Mininet - Network Emulation'),
        ('threading', 'Threading - Concurrent Execution'),
        ('asyncio', 'AsyncIO - Asynchronous Programming')
    ]
    
    missing_modules = []
    for module, display_name in required_modules:
        try:
            __import__(module)
            print(f"✅ {display_name}")
        except ImportError:
            missing_modules.append(display_name)
            print(f"❌ {display_name}")
    
    if missing_modules:
        print(f"\n🚫 Missing required modules:")
        for module in missing_modules:
            print(f"   - {module}")
        print("\nInstallation commands:")
        print("  pip3 install torch numpy PyYAML")
        print("  sudo apt-get install mininet")
        return False
    
    # Enhanced system resource check
    try:
        import psutil
        memory_gb = psutil.virtual_memory().total / (1024**3)
        cpu_count = psutil.cpu_count()
        
        if memory_gb < 2:
            print(f"⚠️  Warning: Low memory ({memory_gb:.1f}GB). Minimum 2GB recommended.")
        if cpu_count < 2:
            print(f"⚠️  Warning: Single CPU core detected. Multi-core recommended.")
        
        print(f"💻 System: {memory_gb:.1f}GB RAM, {cpu_count} CPU cores")
        
    except ImportError:
        print("ℹ️  Install psutil for system resource monitoring: pip3 install psutil")
    
    # Enhanced network capability check
    try:
        result = os.system("which ovs-vsctl > /dev/null 2>&1")
        if result == 0:
            print("✅ Open vSwitch utilities available")
        else:
            print("⚠️  Open vSwitch utilities not found. May cause networking issues.")
    except Exception:
        pass
    
    print("✅ Enhanced environment validation completed")
    return True

async def enhanced_main():
    """Enhanced main async function with comprehensive monitoring"""
    # Enhanced argument parsing
    parser = argparse.ArgumentParser(description="Enhanced Federated Firewall System")
    parser.add_argument('--config', default='config/simple_config.yaml', help='Configuration file path')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Logging level')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--dry-run', action='store_true', help='Validate configuration without running')
    parser.add_argument('--performance-mode', action='store_true', help='Enable performance optimizations')
    
    args = parser.parse_args()
    
    # Enhanced environment validation
    if not check_enhanced_environment():
        sys.exit(1)
    
    # Enhanced logging setup
    try:
        logger = setup_logging(args.log_level, args.debug)
        logger.info("Enhanced logging system initialized successfully")
    except Exception as e:
        print(f"CRITICAL: Failed to setup enhanced logging: {e}")
        sys.exit(1)
    
    # Enhanced configuration loading
    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        logger.info("Available configuration files:")
        config_dir = Path("config")
        if config_dir.exists():
            for config_file in config_dir.glob("*.yaml"):
                logger.info(f"  - {config_file}")
        logger.info("Please ensure the configuration file exists or run setup:")
        logger.info("  sudo env \"PATH=$PATH\" python3 scripts/setup_system.py")
        sys.exit(1)
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Enhanced configuration loaded successfully from: {config_path}")
    except Exception as e:
        logger.error(f"Failed to load enhanced configuration: {e}")
        sys.exit(1)
    
    # Enhanced configuration validation
    try:
        required_sections = ['mininet', 'phases', 'federated', 'model', 'hyperparameters']
        missing_sections = []
        
        for section in required_sections:
            if section not in config:
                missing_sections.append(section)
        
        if missing_sections:
            logger.error(f"Missing required configuration sections: {missing_sections}")
            sys.exit(1)
        
        # Enhanced configuration validation
        mininet_config = config.get('mininet', {})
        if mininet_config.get('num_clients', 0) < 1:
            logger.error("Invalid number of clients in configuration")
            sys.exit(1)
        
        phases_config = config.get('phases', {})
        if phases_config.get('learning_rounds', 0) < 1:
            logger.error("Invalid learning rounds in configuration")
            sys.exit(1)
        
        logger.info("Enhanced configuration validation passed")
        
    except Exception as e:
        logger.error(f"Enhanced configuration validation error: {e}")
        sys.exit(1)
    
    # Dry run mode
    if args.dry_run:
        logger.info("DRY RUN MODE: Configuration and environment validated successfully")
        logger.info("System is ready to run. Use without --dry-run to start the system.")
        return
    
    # Enhanced system information display
    logger.info("=" * 80)
    logger.info("🔥 ENHANCED FEDERATED FIREWALL SYSTEM")
    logger.info("=" * 80)
    logger.info(f"Configuration: {config_path}")
    logger.info(f"Log Level: {args.log_level}")
    logger.info(f"Debug Mode: {args.debug}")
    logger.info(f"Performance Mode: {args.performance_mode}")
    logger.info(f"Clients: {config['mininet']['num_clients']}")
    logger.info(f"Learning Rounds: {config['phases']['learning_rounds']}")
    logger.info(f"Testing Rounds: {config['phases']['testing_rounds']}")
    logger.info(f"Learning Duration: {config['phases']['learning_duration']}s per round")
    logger.info(f"Testing Duration: {config['phases']['testing_duration']}s per round")
    logger.info(f"Federated Learning: {config['federated']['local_epochs']} local epochs")
    logger.info(f"Model Architecture: {config['hyperparameters']['hidden_sizes'][0]}D hidden")
    logger.info(f"Adaptive Hyperparameters: {config['hyperparameters']['tuning']['enabled']}")
    logger.info("=" * 80)
    
    # Enhanced network manager initialization
    try:
        logger.info("Initializing enhanced network manager...")
        network_manager = RobustNetworkManager(config)
        logger.info("Enhanced network manager initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize enhanced network manager: {e}")
        if args.debug:
            logger.error("Full traceback:")
            logger.error(traceback.format_exc())
        sys.exit(1)
    
    # Enhanced performance optimizations
    if args.performance_mode:
        logger.info("Applying enhanced performance optimizations...")
        try:
            # System optimizations
            os.system("echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1")
            os.system("echo 1 | sudo tee /proc/sys/net/core/netdev_max_backlog > /dev/null 2>&1")
            logger.info("Enhanced performance optimizations applied")
        except Exception as e:
            logger.warning(f"Some performance optimizations failed: {e}")
    
    # Record enhanced start time
    start_time = time.time()
    network_manager.start_time = start_time
    
    try:
        # Enhanced system startup
        logger.info("🚀 LAUNCHING ENHANCED SYSTEM...")
        await network_manager.start_system()
        
        # Enhanced system monitoring loop
        logger.info("✅ ENHANCED SYSTEM OPERATIONAL")
        logger.info("Press Ctrl+C to stop the system gracefully")
        logger.info("Monitoring system performance and health...")
        
        # Enhanced status reporting
        status_interval = 25  # More frequent status updates
        performance_check_interval = 60
        next_status_time = time.time() + status_interval
        next_performance_check = time.time() + performance_check_interval
        
        status_count = 0
        
        while network_manager.is_running:
            current_time = time.time()
            
            # Enhanced status update
            if current_time >= next_status_time:
                try:
                    elapsed_time = current_time - start_time
                    system_status = network_manager.get_system_status()
                    status_count += 1
                    
                    # Enhanced status logging
                    logger.info(f"📊 ENHANCED STATUS #{status_count} - Runtime: {elapsed_time:.0f}s")
                    logger.info(f"   Phase: {system_status['current_phase'].upper()}")
                    logger.info(f"   Clients: {system_status['num_clients']} active")
                    logger.info(f"   Network: {'✅ Active' if system_status['network_active'] else '❌ Inactive'}")
                    
                    # Enhanced system metrics
                    if 'system_metrics' in system_status:
                        metrics = system_status['system_metrics']
                        logger.info(f"   Metrics: Avg Accuracy={metrics.get('average_accuracy', 0):.3f}, "
                                  f"Packets={metrics.get('total_packets_processed', 0)}, "
                                  f"Fed Rounds={metrics.get('federated_rounds', 0)}")
                    
                    next_status_time = current_time + status_interval
                    
                except Exception as e:
                    logger.error(f"Enhanced status update error: {e}")
                    next_status_time = current_time + status_interval
            
            # Enhanced performance check
            if current_time >= next_performance_check:
                try:
                    await enhanced_performance_check(network_manager, elapsed_time, logger)
                    next_performance_check = current_time + performance_check_interval
                except Exception as e:
                    logger.error(f"Enhanced performance check error: {e}")
                    next_performance_check = current_time + performance_check_interval
            
            await asyncio.sleep(3)  # Reduced sleep for more responsive monitoring
        
    except KeyboardInterrupt:
        logger.info("🛑 ENHANCED SHUTDOWN REQUESTED BY USER")
    except Exception as e:
        logger.error(f"💥 ENHANCED SYSTEM ERROR: {e}")
        if args.debug:
            logger.error("Enhanced full traceback:")
            logger.error(traceback.format_exc())
    finally:
        # Enhanced graceful shutdown
        try:
            total_runtime = time.time() - start_time
            logger.info(f"ℹ️  INITIATING ENHANCED SHUTDOWN (Total Runtime: {total_runtime:.1f}s)")
            
            # Enhanced shutdown process
            await network_manager.stop_system()
            
            # Enhanced cleanup if performance mode was used
            if args.performance_mode:
                try:
                    logger.info("Restoring system performance settings...")
                    os.system("echo 'powersave' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1")
                except Exception as e:
                    logger.debug(f"Performance settings restoration error: {e}")
            
            logger.info("✅ ENHANCED SHUTDOWN COMPLETE")
            logger.info("Thank you for using the Enhanced Federated Firewall System!")
            logger.info(f"Total system runtime: {total_runtime:.1f} seconds")
            
        except Exception as shutdown_error:
            logger.error(f"Enhanced shutdown error: {shutdown_error}")
            sys.exit(1)

async def enhanced_performance_check(network_manager, elapsed_time, logger):
    """Perform enhanced performance checks and optimizations"""
    try:
        logger.info("🔍 Enhanced performance check in progress...")
        
        # Get system status
        status = network_manager.get_system_status()
        
        # Check client health
        healthy_clients = sum(1 for client in status.get('clients_status', []) 
                            if client.get('is_running', False))
        total_clients = len(status.get('clients_status', []))
        
        if healthy_clients < total_clients:
            logger.warning(f"⚠️  Client health issue: {healthy_clients}/{total_clients} clients running")
        
        # Check system metrics trends
        metrics = status.get('system_metrics', {})
        avg_accuracy = metrics.get('average_accuracy', 0)
        
        if avg_accuracy > 0:
            if avg_accuracy < 0.5:
                logger.warning(f"⚠️  Low system accuracy detected: {avg_accuracy:.3f}")
            elif avg_accuracy > 0.8:
                logger.info(f"🎯 Excellent system accuracy: {avg_accuracy:.3f}")
        
        # Memory usage check (if psutil available)
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            cpu_percent = psutil.cpu_percent(interval=1)
            
            if memory_percent > 80:
                logger.warning(f"⚠️  High memory usage: {memory_percent:.1f}%")
            if cpu_percent > 90:
                logger.warning(f"⚠️  High CPU usage: {cpu_percent:.1f}%")
            
            logger.debug(f"System resources: CPU={cpu_percent:.1f}%, Memory={memory_percent:.1f}%")
            
        except ImportError:
            pass
        
        logger.info("✅ Enhanced performance check completed")
        
    except Exception as e:
        logger.error(f"Enhanced performance check error: {e}")

def main():
    """Enhanced main function with comprehensive error handling"""
    try:
        # Enhanced environment check before async execution
        if not check_enhanced_environment():
            sys.exit(1)
        
        # Run enhanced async main
        asyncio.run(enhanced_main())
        
    except KeyboardInterrupt:
        print("\n🛑 Enhanced system interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"💥 Enhanced fatal error: {e}")
        import traceback
        print("Enhanced error traceback:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()