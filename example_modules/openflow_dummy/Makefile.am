TOP=../..
OFSRC=@openflowsrc@

<<<<<<< HEAD
CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow -I$(TOP)/netfpga-packet-generator-c-library/include
=======
CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
>>>>>>> Changes made to the project over summer at T LABS
LDFLAGS+=-L$(TOP) -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow

lib_LTLIBRARIES=libopenflow_dummy.la

libopenflow_dummy_la_SOURCES= dummy.c # vconn.c