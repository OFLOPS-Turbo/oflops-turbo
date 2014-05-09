TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP)

LDADD=-ldl -lpcap -loflops_test


lib_LTLIBRARIES=liboflops_debug.la

liboflops_debug_la_SOURCES= debug.c
