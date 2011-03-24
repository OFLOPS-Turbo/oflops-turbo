#!/bin/bash

table=1;
for flow_num in 1 25 50 75 `seq 50 50 300`; do
   for try in `seq 1 1 5`; do 
	sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
	    /testbed/data/nec/mod_flow/config-nec-mod-flow.cfg \
	    | tee /tmp/oflops.cfg
	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do 
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	mv oflops.log /testbed/data/nec/mod_flow/exact/`printf "%05d" $flow_num`-$try-oflops.log;
	dpctl del-flows ptcp:
	sleep 20;
	done
done

table=0;
#for flow_num in 1 25 50 75 `seq 50 50 300` `seq 500 500 3000` 2999; do
for flow_num in `seq 500 500 3000`; do
    for try in `seq 1 1 5`; do 
	sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
 	    /testbed/data/nec/mod_flow/config-nec-mod-flow.cfg \
	    | tee /tmp/oflops.cfg
	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do 
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	mv oflops.log /testbed/data/nec/mod_flow/wild/`printf "%05d" $flow_num`-$try-oflops.log;
	dpctl del-flows ptcp:
	sleep 20;
	done
done