#!/bin/bash

# Function to display script options
function show_options {
  clear
  echo "========================================"
  echo "  Welcome to CRYPTOGRAPHYTUBE Cloud GPU Mining Script"
  echo "========================================"
  echo "1. Start Mining"
  echo "2. Check GPU Availability"
  echo "3. Exit"
  echo "========================================"
  read -p "Please select an option: " option
}

# Function to check GPU availability
function check_gpu {
  clear
  echo "Checking available GPUs for CRYPTOGRAPHYTUBE..."
  python3 -c "import tensorflow as tf; print('Available GPUs:', tf.config.list_physical_devices('GPU'))"
  echo "========================================"
  read -p "Press Enter to return to CRYPTOGRAPHYTUBE main menu."
  show_options
}

# Function to start mining
function start_mining {
  clear
  echo "Starting CRYPTOGRAPHYTUBE mining process..."
  
  # Ask for the necessary mining details
  read -p "Enter your Wallet Address for CRYPTOGRAPHYTUBE mining: " wallet_address
  read -p "Enter the Mining Pool Address: " pool_address
  echo "Do you want to use a remote GPU API for mining? (yes/no)"
  read -p "Enter your choice: " use_api
  
  # Check if API key is required
  if [[ "$use_api" == "yes" ]]; then
    read -p "Enter your API Key: " api_key
    gpu_source="Remote GPU via API"
  else
    api_key=""
    gpu_source="Local GPU"
  fi
  
  # Install required dependencies
  echo "Installing dependencies for CRYPTOGRAPHYTUBE..."
  apt-get update && apt-get install -y build-essential cmake libssl-dev libcurl4-openssl-dev libjansson-dev
  
  # Clone mining software
  echo "Cloning CRYPTOGRAPHYTUBE mining software repository..."
  git clone https://github.com/xmrig/xmrig.git
  cd xmrig
  
  # Build the mining software
  echo "Building CRYPTOGRAPHYTUBE mining software..."
  mkdir build
  cd build
  cmake ..
  make -j$(nproc)
  
  # Start mining
  echo "Starting CRYPTOGRAPHYTUBE mining with $gpu_source..."
  if [[ -z "$api_key" ]]; then
    ./xmrig -o $pool_address -u $wallet_address -p x --cuda
  else
    ./xmrig -o $pool_address -u $wallet_address -p x --cuda --api-port 8080 --api-key $api_key
  fi
}

# Display menu and process options
show_options

while true; do
  case $option in
    1) start_mining ;;
    2) check_gpu ;;
    3) exit ;;
    *) echo "Invalid option. Please try again." ;;
  esac
done
