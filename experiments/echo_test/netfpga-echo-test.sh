#!/bin/bash

if [ -e oflops.log ]; then 
    rm oflops.log;
fi

type=netfpga;

for try in `seq 1 10`; do 
    for delay in 4000000 3000000 2000000 1000000 500000 250000; do
	sleep 20;
	sed -e "s/%delay%/$delay/g" \
	    /testbed/data/$type/echo_test/config-$type-echo-test.cfg \
	    > /tmp/oflops.cfg
	./oflops -i  /tmp/oflops.cfg;
	mv oflops.log /testbed/data/$type/echo_test/`printf "%07d" $delay`-`printf "%03d" $try`-oflops.log;
    done
    
    
done