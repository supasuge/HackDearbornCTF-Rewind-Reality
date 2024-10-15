#!/bin/bash
# This script simply downloads `snicat` from the latest release on GitHub.
#   - It detects the OS and architecture of the system.
#   - Downloads the appropriate binary.
#   - Makes it executable (on Linux/Mac).
#   - Moves it to /usr/local/bin (on Linux/Mac).
#   - Provides instructions for usage.
# Snicat is a tool offered by CTFd used for there hosted CTF tier's. It's a tool made by the CTFd team that offers a netcat like alternative used to connect to a remote HTTPS host in which a TCP connection is forwarded internally and through
# the established HTTPS connection. 
# Wrote this because it wouldn't allow me to request a TCP port so people could just use netcat to connect to the host... only snicat would work. 
# Wanted to make it easy for people to download and use.

# ANSI color codes for status messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print messages with color
print_status() {
    local type="$1"
    local message="$2"
    case "$type" in
        "info")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "success")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "warning")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "error")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Check if wget or curl is installed
if command -v wget > /dev/null 2>&1; then
    DOWNLOADER="wget -q -O"
elif command -v curl > /dev/null 2>&1; then
    DOWNLOADER="curl -sL -o"
else
    print_status "error" "Neither wget nor curl is installed. Please install one of them and rerun the script."
    exit 1
fi

# Detect OS and Architecture
OS=$(uname -s)
ARCH=$(uname -m)

print_status "info" "Detected OS: $OS, Architecture: $ARCH"

# Map OS names to expected values
case "$OS" in
    Linux)
        OS_NAME="Linux"
        ;;
    Darwin)
        OS_NAME="Darwin"
        ;;
    CYGWIN*|MINGW*|MSYS*|Windows_NT)
        OS_NAME="Windows"
        ;;
    *)
        print_status "error" "Unsupported operating system: $OS"
        exit 1
        ;;
esac

# Map architecture names to expected values
case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="x86_64"
        ;;
    i386|i686)
        ARCH_NAME="i386"
        ;;
    armv7l|armv8l)
        ARCH_NAME="armv7"
        ;;
    aarch64)
        ARCH_NAME="arm64"
        ;;
    *)
        print_status "error" "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Prepare download URL
if [[ "$OS_NAME" == "Linux" || "$OS_NAME" == "Darwin" ]]; then
    URL="https://github.com/CTFd/snicat/releases/latest/download/sc_${OS_NAME}_${ARCH_NAME}"
    FILE="sc"
elif [[ "$OS_NAME" == "Windows" ]]; then
    URL="https://github.com/CTFd/snicat/releases/latest/download/sc_Windows_x86_64.exe"
    FILE="sc_Windows_x86_64.exe"
else
    print_status "error" "Unsupported operating system: $OS_NAME"
    exit 1
fi

# Download snicat
print_status "info" "Downloading snicat from $URL..."
$DOWNLOADER "$FILE" "$URL"

if [[ $? -ne 0 ]]; then
    print_status "error" "Failed to download snicat."
    exit 1
fi

# Make it executable if on Linux/Mac
if [[ "$OS_NAME" == "Linux" || "$OS_NAME" == "Darwin" ]]; then
    chmod +x "$FILE"
    print_status "success" "Downloaded and set executable permission for snicat."

    # On Mac, remove the quarantine attribute if present
    if [[ "$OS_NAME" == "Darwin" ]]; then
        print_status "info" "Checking for quarantine attribute on macOS..."
        xattr -d com.apple.quarantine "$FILE" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            print_status "success" "Removed quarantine attribute."
        else
            print_status "warning" "No quarantine attribute found or could not be removed."
        fi
    fi

    # Move the binary to /usr/local/bin for global access
    print_status "info" "Installing snicat to /usr/local/bin..."

    # Check if /usr/local/bin is in PATH
    if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
        print_status "warning" "/usr/local/bin is not in your PATH. You may need to add it."
    fi

    # Check if we have write permission to /usr/local/bin
    if [ -w "/usr/local/bin" ]; then
        mv "$FILE" "/usr/local/bin/sc"
    else
        # Prompt for sudo password to move the file
        print_status "info" "Elevated permissions are required to install to /usr/local/bin."
        sudo mv "$FILE" "/usr/local/bin/sc"
        if [[ $? -ne 0 ]]; then
            print_status "error" "Failed to move snicat to /usr/local/bin."
            exit 1
        fi
    fi

    print_status "success" "snicat installed to /usr/local/bin/sc."

elif [[ "$OS_NAME" == "Windows" ]]; then
    print_status "success" "Downloaded snicat for Windows."
    print_status "info" "Please move '$FILE' to a directory in your PATH to use it globally."
    # Optionally, provide instructions for Windows users
fi

# Execute snicat to verify installation
print_status "info" "Running snicat to verify installation..."

if [[ "$OS_NAME" == "Linux" || "$OS_NAME" == "Darwin" ]]; then
    sc --help
elif [[ "$OS_NAME" == "Windows" ]]; then
    cmd /c "$FILE" --help
fi

if [[ $? -eq 0 ]]; then
    print_status "success" "snicat ran successfully."
else
    print_status "error" "Failed to run snicat."
    exit 1
fi

# Provide instructions for usage
print_status "info" "You can now use snicat globally with the following commands:"
echo -e "${GREEN}sc <hostname> <port>${NC}"
echo -e "${GREEN}sc -bind <port> <hostname>${NC}"

exit 0
