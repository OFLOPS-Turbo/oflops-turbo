#!/bin/bash

rm oflops.log

type=hp

for flow_num in 1 10 25 50 75 `seq 100 100 500` `seq 600 200 1000`; do
    for try in `seq 1 100`; do 
	table=1;
	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	    dpctl del-flows tcp:10.1.1.2:6000
	    sleep 20;
	    sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
		/testbed/data/$type/mod_flow/config-$type-mod-flow.cfg \
		| tee /tmp/oflops.cfg
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	mv oflops.log /testbed/data/$type/mod_flow/wild/`printf "%05d" $flow_num`-$try-oflops.log;
	
	table=0;
	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	    dpctl del-flows tcp:10.1.1.2:6000
	    sleep 20;
	    sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
 		/testbed/data/$type/mod_flow/config-$type-mod-flow.cfg \
		| tee /tmp/oflops.cfg
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	mv oflops.log /testbed/data/$type/mod_flow/exact/`printf "%05d" $flow_num`-$try-oflops.log;
    done
done
