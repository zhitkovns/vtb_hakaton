#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building Security Scanner Project${NC}"
echo "========================================"

# Configuration
SRC_DIR="../src/main/java"
BUILD_DIR="../build/classes"
JAVAC="javac"
JAVAC_FLAGS="-encoding UTF-8 -Xlint:deprecation"

# Create build directory
echo -e "${YELLOW}Creating build directory...${NC}"
mkdir -p $BUILD_DIR

# Check if source directory exists
if [ ! -d "$SRC_DIR" ]; then
    echo -e "${RED} Source directory not found: $SRC_DIR${NC}"
    echo "Please run this script from the project root directory"
    exit 1
fi

# Find all Java files
echo -e "${YELLOW}🔍 Finding Java source files...${NC}"
JAVA_FILES=$(find $SRC_DIR -name "*.java")

if [ -z "$JAVA_FILES" ]; then
    echo -e "${RED} No Java files found in $SRC_DIR${NC}"
    exit 1
fi

echo -e "${GREEN} Found $(echo "$JAVA_FILES" | wc -l) Java files${NC}"

# Compile Java files
echo -e "${YELLOW} Compiling Java files...${NC}"
$JAVAC $JAVAC_FLAGS -d $BUILD_DIR $JAVA_FILES

# Check compilation result
if [ $? -eq 0 ]; then
    echo -e "${GREEN} Build successful!${NC}"
    echo -e "${BLUE} Build summary:${NC}"
    echo "  - Build directory: $(pwd)/$BUILD_DIR"
    echo "  - Compiled classes: $(find $BUILD_DIR -name "*.class" | wc -l)"
    echo "  - Main classes:"
    echo "      * com.securityscanner.scanner.OpenAPIParserSimple"
    echo "      * com.securityscanner.scanner.BankingAPIScanner"
else
    echo -e "${RED} Build failed!${NC}"
    exit 1
fi

# Create run script
echo -e "${YELLOW} Creating run script...${NC}"
cat > run.sh << 'EOF'
#!/bin/bash
./run-scanner.sh "$@"
EOF
chmod +x run.sh

echo -e "${GREEN} Build completed successfully!${NC}"
echo -e "${BLUE} Now you can run: ./run-scanner.sh [command]${NC}"