TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
LDFLAGS+=-L$(TOP) -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow

lib_LTLIBRARIES=libopenflow_path_delay.la

libopenflow_path_delay_la_SOURCES= path_delay.c # vconn.c