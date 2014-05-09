TOP=../..
OFSRC=@openflowsrc@

AM_CFLAGS=-Wall -I$(OFSRC)/include -I$(TOP) -I$(TOP)/netfpga-packet-generator-c-library/include \
	-Wshadow # -I$(OFSRC)/lib /testbed/oflops/example_modules/openflow_action_delay
AM_LDFLAGS=-L$(TOP) -lm -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow

lib_LTLIBRARIES=libopenflow_action_delay.la

libopenflow_action_delay_la_SOURCES= action_delay.c # msg.h msg.c # vconn.c
