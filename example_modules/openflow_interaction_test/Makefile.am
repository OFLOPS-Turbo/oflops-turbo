TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
AM_LDFLAGS=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test

lib_LTLIBRARIES=libof_interaction_test.la

libof_interaction_test_la_SOURCES= interaction_test.c
