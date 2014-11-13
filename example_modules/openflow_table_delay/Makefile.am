TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -lm -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow

lib_LTLIBRARIES=libopenflow_table_delay.la

libopenflow_table_delay_la_SOURCES= table_delay.c
