#!/bin/sh
echo Generating autoconf/automake goo...
autoreconf -I m4 --install --force $@

echo Downloading and building netfpga-packet-generator-c-library
# git submodule init && \
#	git submodule update && \
	cd netfpga-packet-generator-c-library && \
       	./autogen.sh && \
       	./configure && \
	make
