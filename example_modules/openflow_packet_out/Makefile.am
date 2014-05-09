TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test

lib_LTLIBRARIES=libof_packet_out.la

libof_packet_out_la_SOURCES= packet_out.c
