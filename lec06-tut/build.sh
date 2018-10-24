#!/bin/bash

VER=2.52b
AFL=afl-$VER
TAR=$AFL.tgz
URL=http://lcamtuf.coredump.cx/afl/releases/$TAR

if [[ ! -e afl-$VER ]]; then
  if [[ ! -e $TAR ]]; then
    wget $URL
  fi
  tar zxvf $TAR
fi

(cd $AFL; make)