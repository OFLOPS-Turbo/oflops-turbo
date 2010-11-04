TOP=../..
OFSRC=@openflowsrc@

<<<<<<< HEAD
CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow  -I$(TOP)/netfpga-packet-generator-c-library/include # -I$(OFSRC)/lib
=======
CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow # -I$(OFSRC)/lib
>>>>>>> Changes made to the project over summer at T LABS
LDFLAGS+=-L$(TOP) -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow -lm

lib_LTLIBRARIES=libopenflow_vlan_mod.la

libopenflow_vlan_mod_la_SOURCES=vlan_mod.c
