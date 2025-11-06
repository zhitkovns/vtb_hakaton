#!/bin/bash

# Simple runner for Security Scanner
# Usage: ./run.sh

# Configuration
BUILD_DIR="../build/classes"
CONFIG_FILE="scanner-config.properties"
PARSER_CLASS="com.securityscanner.scanner.OpenAPIParserSimple"
SCANNER_CLASS="com.securityscanner.scanner.BankingAPIScanner"

echo "Starting Security Scanner..."
echo "================================"

# Check if build exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Build directory not found: $BUILD_DIR"
    echo "Please run ./build.sh first"
    exit 1
fi

# Check if main classes exist
if [ ! -f "$BUILD_DIR/com/securityscanner/scanner/OpenAPIParserSimple.class" ]; then
    echo "Compiled classes not found"
    echo "Please run ./build.sh first"
    exit 1
fi

# Check if config file exists, create default if not
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating default configuration file..."
    cat > "$CONFIG_FILE" << 'EOF'
# Security Scanner Configuration
# Generated on: $(date)

# API Settings
api.base_url=https://vbank.open.bankingapi.ru
api.timeout=5000

# Scanner Settings
scanner.test_endpoints=true
scanner.check_security=true
scanner.verbose_output=true

# Output Settings
output.directory=.
output.format=json

# Parser Settings
parser.auto_save=true
parser.analyze_security=true
EOF
    echo "Created default config: $CONFIG_FILE"
fi

echo "Using config: $CONFIG_FILE"
echo ""

# Run OpenAPI Parser first
echo "Step 1: Running OpenAPI Parser..."
java -cp "$BUILD_DIR" "$PARSER_CLASS"

if [ $? -ne 0 ]; then
    echo "Parser finished with warnings, continuing..."
fi

echo ""

# Run Security Scanner
echo "Step 2: Running Security Scanner..."
java -cp "$BUILD_DIR" "$SCANNER_CLASS"

echo ""
echo "Security scan completed!"
echo "Check generated files in current directory"