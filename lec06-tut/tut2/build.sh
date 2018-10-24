#!/bin/bash

# 
# based on https://releases.llvm.org/3.8.1/docs/LibFuzzer.html
# modified to use libFuzzer.a and run on ubuntu 18.04LTS
# 

if [[ ! -e openssl-1.0.1f.tar.gz ]]; then
  wget https://www.openssl.org/source/openssl-1.0.1f.tar.gz
  tar xf openssl-1.0.1f.tar.gz
  COV_FLAGS="-fsanitize-coverage=edge,indirect-calls" # -fsanitize-coverage=8bit-counters
  (cd openssl-1.0.1f/ && ./config &&
    make -j 32 CC="clang -g -fsanitize=address $COV_FLAGS")
  
  # Get examples of key/pem files.
  git clone https://github.com/hannob/selftls
  cp selftls/server* . -v
fi

# Build the fuzzer.
clang++ -g handshake-fuzz.cc  -fsanitize=address -Iopenssl-1.0.1f/include  \
        openssl-1.0.1f/libssl.a openssl-1.0.1f/libcrypto.a \
        /usr/lib/llvm-6.0/lib/libFuzzer.a