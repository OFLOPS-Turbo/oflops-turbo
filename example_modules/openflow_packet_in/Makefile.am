TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
LDFLAGS+=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test


lib_LTLIBRARIES=libof_packet_in.la

libof_packet_in_la_SOURCES= pktin.c
