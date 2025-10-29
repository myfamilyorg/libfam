#!/bin/bash

# Define the target directory for the library
LIB_VERSION="1.0.0"
LIB_DIR="/usr/lib/libfam-${LIB_VERSION}"
CZIP_BIN=./target/bin/czip
CZIP_INSTALL_DIR=/usr/local/bin

# Ensure directory exists
mkdir -p $LIB_DIR;

# Copy the shared library to the subdirectory
cp target/lib/libfam.so "$LIB_DIR/libfam.so"

# Add ld config
echo "/usr/lib/libfam-${LIB_VERSION}" > /etc/ld.so.conf.d/fam.conf

# Update the dynamic linker cache
ldconfig

# Remove any existing includes
rm -rf /usr/include/libfam

# Copy include directory
cp -rp src/include/libfam /usr/include

# Copy czip
if [ -e ${CZIP_BIN} ]; then
	mkdir -p ${CZIP_INSTALL_DIR}
	cp ${CZIP_BIN} ${CZIP_INSTALL_DIR}
fi
