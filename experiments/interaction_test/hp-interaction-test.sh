#!/bin/bash 

query_delay=120000000;
for try in `seq 1 20`; do 
    while [ ! -e oflops.log ]; do 
	dpctl del-flows tcp:10.1.1.2:6000;
	sleep 20;
	sed -e "s/%query_delay%/$query_delay/g" \
	    /testbed/data/hp/interaction_delay/config-hp-interaction-test.cfg \
	    > /tmp/oflops.cfg;
	/testbed/oflops/oflops -i /tmp/oflops.cfg;
    done
    echo /testbed/data/hp/interaction_delay/no_stat/$try-oflops.log;
    mv oflops.log /testbed/data/hp/interaction_delay/no_stat/$try-oflops.log;
done

query_delay=1000000;
for try in `seq 1 20`; do 
    while [ ! -e oflops.log ]; do 
	dpctl del-flows tcp:10.1.1.2:6000;
	sleep 20;
	sed -e "s/%query_delay%/$query_delay/g" \
	    /testbed/data/hp/interaction_delay/config-hp-interaction-test.cfg \
	    > /tmp/oflops.cfg
	/testbed/oflops/oflops -i /tmp/oflops.cfg
    done
    echo /testbed/data/hp/interaction_delay/stat/$try-oflops.log;
    mv oflops.log /testbed/data/hp/interaction_delay/stat/$try-oflops.log;
done