#!/bin/bash

ulimit -c 0

#for flow_num in 1 10 25 50 75 `seq 50 50 450` `seq 500 100 1000`; do
#for flow_num in 1 25 50 75 `seq 50 50 300`; do
for try in `seq 21 100`; do 
    for flow_num in 1 10 25 50 75 `seq 100 100 500` `seq 600 200 1000`; do
	table=1;
	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do 
	    dpctl del-flows ptcp:
	    sleep 30;
	    sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
		/testbed/data/nec/add_flow/config-nec-add-flow.cfg \
		| tee /tmp/oflops.cfg
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	mv oflops.log /testbed/data/nec/add_flow/exact/`printf "%05d" $flow_num`-$try-oflops.log;
    done
    
    table=0;
    while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do 
	dpctl del-flows ptcp:
	sleep 30;
	sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
 	    /testbed/data/nec/add_flow/config-nec-add-flow.cfg \
	    | tee /tmp/oflops.cfg
	/testbed/oflops/oflops -i /tmp/oflops.cfg
    done
    mv oflops.log /testbed/data/nec/add_flow/wild/`printf "%05d" $flow_num`-$try-oflops.log;
done
