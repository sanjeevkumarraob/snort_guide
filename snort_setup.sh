#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SNORT_VERSION="2.9.20"
DAQ_VERSION="2.0.7"

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Function to check command success
check_status() {
    if [ $? -eq 0 ]; then
        print_message "$1 completed successfully"
        return 0
    else
        print_error "$1 failed"
        if [ "$2" = "critical" ]; then
            print_error "Critical error occurred. Exiting installation."
            exit 1
        fi
        return 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check Ubuntu version
    if ! grep -q "Ubuntu" /etc/os-release; then
        print_error "This script is designed for Ubuntu systems only"
        exit 1
    fi

    # Check disk space (need at least 2GB free)
    free_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$free_space" -lt 2 ]; then
        print_error "Insufficient disk space. Need at least 2GB free."
        exit 1
    fi

    # Check memory (need at least 1GB free)
    free_mem=$(free -m | awk 'NR==2 {print $4}')
    if [ "$free_mem" -lt 1024 ]; then
        print_warning "Low memory available. Installation might be slow."
    fi

    print_message "System requirements check passed"
}

# Function to get network interface
get_network_interface() {
    print_info "Available network interfaces:"
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
    echo "$interfaces"
    
    while true; do
        read -p "Enter the network interface to use [default: eth0]: " INTERFACE
        INTERFACE=${INTERFACE:-eth0}
        if ip link show "$INTERFACE" >/dev/null 2>&1; then
            print_message "Using interface: $INTERFACE"
            break
        else
            print_error "Interface $INTERFACE does not exist. Please try again."
        fi
    done
}

# Function to confirm installation
confirm_installation() {
    print_warning "This script will install Snort $SNORT_VERSION on your system."
    print_warning "Please ensure you have a stable internet connection."
    print_warning "This installation will:"
    echo "  1. Update system packages"
    echo "  2. Install required dependencies"
    echo "  3. Install DAQ $DAQ_VERSION"
    echo "  4. Install Snort $SNORT_VERSION"
    echo "  5. Configure Snort as a service"
    
    read -p "Do you want to continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_message "Installation cancelled"
        exit 1
    fi
}

# Function to backup existing configuration
backup_existing() {
    if [ -d "/etc/snort" ]; then
        print_info "Backing up existing Snort configuration..."
        backup_dir="/etc/snort.backup.$(date +%Y%m%d_%H%M%S)"
        sudo cp -r /etc/snort "$backup_dir"
        check_status "Configuration backup" "non-critical"
    fi
}

# Function to install dependencies
install_dependencies() {
    print_info "Installing required dependencies..."
    sudo apt install -y build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev \
    libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkgconf \
    libtool automake libtirpc-dev libluajit-5.1-dev libluajit-5.1-common
    check_status "Dependencies installation" "critical"

}

# Function to configure rules and paths
configure_paths_and_rules() {
    print_info "Configuring Snort paths and rules..."

    # Create all necessary directories
    sudo mkdir -p /etc/snort/rules
    sudo mkdir -p /etc/snort/preproc_rules
    sudo mkdir -p /etc/snort/so_rules
    sudo mkdir -p /etc/snort/etc
    
    # Create empty rule files
    sudo touch /etc/snort/rules/white_list.rules
    sudo touch /etc/snort/rules/black_list.rules
    sudo touch /etc/snort/rules/local.rules
    
    # Update paths in snort.conf
    print_info "Updating paths in snort.conf..."
    sudo sed -i 's/var RULE_PATH ..\/rules/var RULE_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    sudo sed -i 's/var SO_RULE_PATH ..\/so_rules/var SO_RULE_PATH \/etc\/snort\/so_rules/' /etc/snort/snort.conf
    sudo sed -i 's/var PREPROC_RULE_PATH ..\/preproc_rules/var PREPROC_RULE_PATH \/etc\/snort\/preproc_rules/' /etc/snort/snort.conf
    
    # Update white/black list paths
    sudo sed -i 's/var WHITE_LIST_PATH ..\/rules/var WHITE_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    sudo sed -i 's/var BLACK_LIST_PATH ..\/rules/var BLACK_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    
    # Set proper permissions
    sudo chmod -R 644 /etc/snort/rules
    sudo chown -R snort:snort /etc/snort/rules
    
    print_info "Verifying file existence..."
    for file in white_list.rules black_list.rules local.rules; do
        if [ ! -f "/etc/snort/rules/$file" ]; then
            print_error "Missing $file, creating it..."
            sudo touch "/etc/snort/rules/$file"
            sudo chmod 644 "/etc/snort/rules/$file"
            sudo chown snort:snort "/etc/snort/rules/$file"
        fi
    done
}

# Function to fix existing installation
fix_paths_and_rules() {
    print_info "Fixing Snort paths and rules..."
    
    # Create missing files
    sudo mkdir -p /etc/snort/rules
    sudo touch /etc/snort/rules/white_list.rules
    sudo touch /etc/snort/rules/black_list.rules
    sudo touch /etc/snort/rules/local.rules
    
    # Fix permissions
    sudo chmod 644 /etc/snort/rules/white_list.rules
    sudo chmod 644 /etc/snort/rules/black_list.rules
    sudo chmod 644 /etc/snort/rules/local.rules
    sudo chown -R snort:snort /etc/snort/rules
    
    # Fix paths in snort.conf
    sudo sed -i 's/var RULE_PATH ..\/rules/var RULE_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    sudo sed -i 's/var WHITE_LIST_PATH ..\/rules/var WHITE_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    sudo sed -i 's/var BLACK_LIST_PATH ..\/rules/var BLACK_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
    
    print_info "Testing configuration..."
    sudo snort -T -c /etc/snort/snort.conf -i ${INTERFACE}
}

# Function to install and configure rules
install_rules() {
    print_info "Setting up Snort rules..."
    
    # Create rules directory if it doesn't exist
    sudo mkdir -p /etc/snort/rules
    sudo mkdir -p /etc/snort/preproc_rules
    sudo mkdir -p /etc/snort/so_rules
    
    # Download and install community rules
    print_info "Downloading community rules..."
    cd ~/snort_src
    wget https://www.snort.org/rules/community -O ~/snort_src/community.tar.gz
    check_status "Rules download"
    
    print_info "Extracting community rules..."
    cd /etc/snort/rules
    sudo tar -xvf ~/snort_src/community.tar.gz
    check_status "Rules extraction"
    
    # Create empty required files
    print_info "Creating additional rule files..."
    sudo touch /etc/snort/rules/white_list.rules
    sudo touch /etc/snort/rules/black_list.rules
    sudo touch /etc/snort/rules/local.rules
    
    # Configure snort.conf
    print_info "Configuring snort.conf..."
    sudo sed -i 's/include \$RULE\_PATH\/#/# include \$RULE\_PATH\//' /etc/snort/snort.conf
    
    # Update rule paths in snort.conf
    sudo sed -i "s/var RULE_PATH ..\/rules/var RULE_PATH \/etc\/snort\/rules/" /etc/snort/snort.conf
    sudo sed -i "s/var SO_RULE_PATH ..\/so_rules/var SO_RULE_PATH \/etc\/snort\/so_rules/" /etc/snort/snort.conf
    sudo sed -i "s/var PREPROC_RULE_PATH ..\/preproc_rules/var PREPROC_RULE_PATH \/etc\/snort\/preproc_rules/" /etc/snort/snort.conf
    
    # Add community rules to snort.conf
    echo "include \$RULE_PATH/community-rules/community.rules" | sudo tee -a /etc/snort/snort.conf
    
    # Set permissions
    sudo chmod -R 644 /etc/snort/rules
    sudo chown -R snort:snort /etc/snort/rules
    
    print_info "Testing Snort configuration..."
    sudo snort -T -c /etc/snort/snort.conf -i ${INTERFACE}
    check_status "Snort configuration test"
}

# Add this function to verify rules installation
verify_rules() {
    print_info "Verifying rules installation..."
    
    if [ ! -f "/etc/snort/rules/community-rules/community.rules" ]; then
        print_error "Community rules file not found"
        print_info "Attempting to fix rules installation..."
        install_rules
    fi
    
    # Check rules loading
    rule_count=$(grep -c "^alert" /etc/snort/rules/community-rules/community.rules 2>/dev/null || echo "0")
    print_info "Found $rule_count rules in community.rules"
    
    if [ "$rule_count" -eq 0 ]; then
        print_warning "No rules found in community.rules"
        return 1
    fi
    
    return 0
}

# Quick fix function for existing installation
fix_rules() {
    print_info "Fixing Snort rules installation..."
    
    # Backup existing snort.conf
    sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.backup
    
    # Download and install community rules
    cd ~/snort_src
    wget https://www.snort.org/rules/community -O community.tar.gz
    sudo tar -xvf community.tar.gz -C /etc/snort/rules/
    
    # Update snort.conf
    sudo sed -i "s/var RULE_PATH ..\/rules/var RULE_PATH \/etc\/snort\/rules/" /etc/snort/snort.conf
    sudo sed -i "s/include \$RULE\_PATH\/#/# include \$RULE\_PATH\//" /etc/snort/snort.conf
    echo "include \$RULE_PATH/community-rules/community.rules" | sudo tee -a /etc/snort/snort.conf
    
    # Set permissions
    sudo chmod -R 644 /etc/snort/rules
    sudo chown -R snort:snort /etc/snort/rules
    
    print_info "Testing new configuration..."
    sudo snort -T -c /etc/snort/snort.conf -i ${INTERFACE}
}

# Main installation function
install_snort() {
    # Update system
    print_info "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    check_status "System update" "critical"

    # Install dependencies
    install_dependencies

    # Create directories
    print_info "Creating source directory..."
    mkdir -p ~/snort_src
    cd ~/snort_src || exit
    check_status "Directory creation" "critical"

    # Install DAQ
    print_info "Installing DAQ..."
    wget "https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz"
    tar -xvzf "daq-${DAQ_VERSION}.tar.gz"
    cd "daq-${DAQ_VERSION}" || exit
    ./configure && make && sudo make install
    check_status "DAQ installation" "critical"

    # Install Snort
    print_info "Installing Snort..."
    cd ~/snort_src || exit
    wget "https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz"
    tar -xvzf "snort-${SNORT_VERSION}.tar.gz"
    cd "snort-${SNORT_VERSION}" || exit
    
    # Configure with RPC support and proper LuaJIT paths
    print_info "Configuring Snort..."
    export PKG_CONFIG_PATH=/usr/lib/pkgconfig
    CFLAGS="-I/usr/include/tirpc -I/usr/include/luajit-2.1" \
    LDFLAGS="-ltirpc" \
    ./configure --enable-sourcefire \
    --with-luajit-includes=/usr/include/luajit-2.1 \
    --with-luajit-libraries=/usr/lib/x86_64-linux-gnu
    
    check_status "Snort configuration" "critical"
    
    print_info "Compiling Snort..."
    make
    check_status "Snort compilation" "critical"
    
    print_info "Installing Snort..."
    sudo make install
    check_status "Snort installation" "critical"

    # Update shared libraries
    print_info "Updating shared libraries..."
    sudo ldconfig
    check_status "Library update"

    # Create directories and set permissions
    print_info "Creating Snort directories..."
    sudo mkdir -p /etc/snort /etc/snort/rules /etc/snort/preproc_rules \
    /usr/local/lib/snort_dynamicrules /var/log/snort
    check_status "Directory creation"

    print_info "Creating Snort user and group..."
    sudo groupadd snort 2>/dev/null || true
    sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort 2>/dev/null || true
    check_status "User creation"

    print_info "Setting permissions..."
    sudo chmod -R 5775 /etc/snort /var/log/snort /usr/local/lib/snort_dynamicrules
    sudo chown -R snort:snort /etc/snort /var/log/snort /usr/local/lib/snort_dynamicrules
    check_status "Permission setup"

    # Copy configuration files
    print_info "Copying configuration files..."
    cd ~/snort_src/snort-${SNORT_VERSION}/etc/
    sudo cp *.conf* /etc/snort
    sudo cp *.map /etc/snort
    sudo cp *.dtd /etc/snort
    check_status "Configuration file copy"
    
    install_rules
    if ! verify_rules; then
        print_warning "Rules installation needs fixing..."
        fix_rules
    fi

    # Download and install rules
    print_info "Downloading and installing community rules..."
    wget https://www.snort.org/rules/community -O ~/snort_src/community.tar.gz
    tar -xvf ~/snort_src/community.tar.gz -C ~/snort_src
    sudo cp ~/snort_src/community-rules/* /etc/snort/rules/
    check_status "Rules installation"

    # Configure snort.conf
    print_info "Configuring Snort..."
    sudo sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf
    echo 'include $RULE_PATH/community-rules/community.rules' | sudo tee -a /etc/snort/snort.conf
    check_status "Snort configuration"

    # Create systemd service
    print_info "Creating systemd service..."
    sudo tee /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort NIDS Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i ${INTERFACE}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    check_status "Service creation"
    
    configure_paths_and_rules
    
    # Test configuration
    print_info "Testing Snort configuration..."
    sudo snort -T -c /etc/snort/snort.conf -i ${INTERFACE}
    check_status "Configuration test" "critical"

    # Enable and start service
    print_info "Enabling and starting Snort service..."
    sudo systemctl enable snort
    sudo systemctl start snort
    check_status "Service startup"
}

# Clean up function
cleanup() {
    print_info "Cleaning up installation files..."
    rm -rf ~/snort_src
    check_status "Cleanup"
}

# Function to verify installation
verify_installation() {
    print_info "Verifying Snort installation..."
    
    # Check Snort version
    snort --version
    check_status "Version check"
    
    # Check service status
    sudo systemctl status snort
    check_status "Service status check"
    
    # Check rule loading
    sudo snort -T -c /etc/snort/snort.conf -i ${INTERFACE}
    check_status "Rule verification"
}

# Main script execution
main() {
    clear
    echo "======================================"
    echo "  Snort IDS Installation Script"
    echo "  Version: $SNORT_VERSION"
    echo "======================================"
    echo
    
    check_requirements
    confirm_installation
    backup_existing
    get_network_interface
    
    # Install Snort and rules
    install_snort
    
    # Verify entire installation
    verify_installation
    
    # Additional verification for rules
    if ! verify_rules; then
        print_warning "Rules verification failed after installation"
        read -p "Would you like to attempt to fix the rules? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            fix_rules
        else
            print_warning "Skipping rules fix. Manual intervention may be required"
        fi
    fi
    
    cleanup
    
    print_message "Installation complete!"
    print_info "You can:"
    echo "  - Check Snort status with: sudo systemctl status snort"
    echo "  - Monitor alerts with: sudo tail -f /var/log/snort/alert"
    echo "  - Test configuration with: sudo snort -T -c /etc/snort/snort.conf -i ${INTERFACE}"
    echo "  - View rules at: /etc/snort/rules/community-rules/community.rules"
}

# Also add a command-line option to fix rules only
if [ "$1" == "--fix-rules" ]; then
    print_info "Running rules fix only..."
    get_network_interface
    fix_rules
    exit 0
fi

# Run main function
main