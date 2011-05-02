#!/bin/bash 

query_delay=120000000;
for try in `seq 1 20`; do 
    while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	dpctl del-flows tcp:10.1.1.2:6000;
	sleep 20;
	sed -e "s/%query_delay%/$query_delay/g" \
	    /testbed/data/hp/interaction_delay/config-hp-interaction-test.cfg \
	    | tee /tmp/oflops.cfg;
	/testbed/oflops/oflops -i /tmp/oflops.cfg;
    done
    mv oflops.log /testbed/data/hp/interaction_delay/no_stat/$try-oflops.log;
done

query_delay=1000000;
for try in `seq 1 20`; do 
    while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	dpctl del-flows tcp:10.1.1.2:6000;
	sleep 20;
	sed -e "s/%query_delay%/$query_delay/g" \
	    /testbed/data/hp/interaction_delay/config-hp-interaction-test.cfg \
	    | tee /tmp/oflops.cfg
	/testbed/oflops/oflops -i /tmp/oflops.cfg
    done
    mv oflops.log /testbed/data/hp/interaction_delay/stat/$try-oflops.log;
done