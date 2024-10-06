#!/bin/bash

# Script: lazydir.sh
# Description: Automates the creation of challenge directories for CTF categories.
#              Default name of each challenge directory is "CHANGE_ME" simply change the name and begin creating your challenge.
# Author: supasuge
# Date: 2024-04-27

# Exit immediately if a command exits with a non-zero status
set -e

# =======================
# ANSI Color Definitions
# =======================
# Reset
NC='\033[0m' # No Color

# Regular Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'

# Bold
BOLD='\033[1m'

# =======================
# Helper Functions
# =======================

# Function to print error messages
error() {
    echo -e "${RED}${BOLD}ERROR:${NC} $1" >&2
}

# Function to print success messages
success() {
    echo -e "${GREEN}${BOLD}SUCCESS:${NC} $1"
}

# Function to print info messages
info() {
    echo -e "${BLUE}${BOLD}INFO:${NC} $1"
}

# Function to print warning messages
warning() {
    echo -e "${YELLOW}${BOLD}WARNING:${NC} $1"
}

# Function to handle script exit
cleanup() {
    echo -e "\n${MAGENTA}${BOLD}Script terminated.${NC}"
    exit 1
}

# Trap signals for graceful exit
trap cleanup SIGINT SIGTERM

# =======================
# Configuration Variables
# =======================

# Define categories to process, including 'misc'
categories=("web" "rev" "pwn" "forensics" "misc")

# Total number of new challenges to create
total_new_challenges=28

# Number of categories
num_categories=${#categories[@]}

# Calculate base challenges per category and remainder for even distribution
base_challenges=$(( total_new_challenges / num_categories ))  # 5
remainder=$(( total_new_challenges % num_categories ))        # 3

# =======================
# Function Definitions
# =======================

# Function to create directory structure for a single challenge
create_challenge() {
    local category=$1
    local challenge_num=$2
    local challenge_dir="${category}/CHANGE_ME_${challenge_num}"

    if [ -d "${challenge_dir}" ]; then
        warning "Directory ${challenge_dir} already exists. Skipping..."
        return
    fi

    echo -e "${CYAN}${BOLD}Creating${NC} challenge directory: ${challenge_dir}"

    # Create main challenge directory
    if mkdir -p "${challenge_dir}"; then
        info "Created directory: ${challenge_dir}"
    else
        error "Failed to create directory: ${challenge_dir}"
        return 1
    fi

    # Create subdirectories
    for subdir in build dist solution; do
        if mkdir -p "${challenge_dir}/${subdir}"; then
            info "Created subdirectory: ${challenge_dir}/${subdir}"
        else
            error "Failed to create subdirectory: ${challenge_dir}/${subdir}"
            return 1
        fi
    done

    # Create README.md with placeholder content
    cat <<EOF > "${challenge_dir}/README.md"
# CHANGE_ME_${challenge_num}

## Description
Provide a detailed description of the challenge here.

## Files
- **build/**: Contains build-related files such as Dockerfiles or scripts.
- **dist/**: Contains distributed files necessary for the challenge.
- **solution/**: Contains solution scripts and write-ups.

## Notes
- Ensure all necessary dependencies are included in the build process.
- Provide hints if necessary.
EOF

    if [ $? -eq 0 ]; then
        info "Created README.md in ${challenge_dir}"
    else
        error "Failed to create README.md in ${challenge_dir}"
        return 1
    fi

    success "Challenge ${challenge_dir} created successfully."
}

# =======================
# Main Script Execution
# =======================

# Check if script is run from the project root directory
if [ ! -d "crypto" ] || [ ! -d "web" ] || [ ! -d "rev" ] || [ ! -d "pwn" ] || [ ! -d "forensics" ] || [ ! -d "misc" ]; then
    error "Please run this script from the project root directory containing the categories: crypto, web, rev, pwn, forensics, misc."
    exit 1
fi

echo -e "${BOLD}${MAGENTA}==============================${NC}"
echo -e "${BOLD}${MAGENTA}Starting CTF Challenge Setup${NC}"
echo -e "${BOLD}${MAGENTA}==============================${NC}\n"

# Initialize challenge counter
challenge_counter=1

for category in "${categories[@]}"; do
    # Determine the number of challenges for this category
    if [ "$remainder" -gt 0 ]; then
        challenges_in_category=$(( base_challenges + 1 ))
        remainder=$(( remainder - 1 ))
    else
        challenges_in_category=$base_challenges
    fi

    info "Processing category: ${category} with ${challenges_in_category} challenges"

    for ((i=1; i<=challenges_in_category; i++)); do
        create_challenge "${category}" "${i}"
        if [ $? -ne 0 ]; then
            error "Failed to create challenge ${i} in category ${category}. Exiting..."
            exit 1
        fi
        challenge_counter=$(( challenge_counter + 1 ))
    done
done

echo -e "\n${BOLD}${GREEN}All challenge directories have been created successfully.${NC}"
echo -e "${BOLD}${GREEN}Happy CTF-ing!${NC}"
