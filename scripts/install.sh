#!/bin/bash

# Define the target directory for the library
LIB_DIR="/usr/lib"
LIB_VERSION="0.0.1"

# Copy the shared library to the subdirectory
cp target/lib/libfam.so "$LIB_DIR/libfam.so.${LIB_VERSION}"

# Remove any existing symlink in the subdirectory
unlink "$LIB_DIR/libfam.so" 2>/dev/null || true

# Create a symlink for the library
ln -s "$LIB_DIR/libfam.so.${LIB_VERSION}" "$LIB_DIR/libfam.so"

# Update the dynamic linker cache
ldconfig

# Copy include directory
cp -rp src/include/libfam /usr/include
