TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include
LDFLAGS+=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test


lib_LTLIBRARIES=libnf_pktgen_test.la

libnf_pktgen_test_la_SOURCES= nf_pktgen.c