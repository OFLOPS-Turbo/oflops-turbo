#
# $Id: Makefile 4664 2008-11-03 14:50:25Z icing $
#

all: nf2util.o 

nf2util.o: nf2util.c nf2util.h nf2.h
	gcc -g -c nf2util.c

#libnf2.so: nf2util.o
#	gcc -g -shared nf2util.o -o $@

clean :
	rm -rf nf2util.o # libnf2.so

#install: libnf2.so
#	install -d /usr/local/lib
#	install -m 644 libnf2.so /usr/local/lib
#	ln -s -f /usr/local/lib/libnf2.so /usr/local/lib/libnf2regs.so
#	ldconfig

.PHONY: clean
