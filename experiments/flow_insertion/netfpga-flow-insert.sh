#!/bin/bash

type=netfpga

#table=0;
#for flow_num in 1 10 25 50 75 100; do
#for flow_num in `seq 100 50 450` `seq 500 100 1000`; do
#    for try in `seq 1 20`; do
#        while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do
#	        sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
#        	    /testbed/data/$type/mod_flow/config-$type-mod-flow.cfg \
#	            | tee /tmp/oflops.cfg
 #               /testbed/oflops/oflops -i /tmp/oflops.cfg
#        mv oflops.log /testbed/data/$type/mod_flow/exact/`printf "%05d" $flow_num`-$try-oflops.log;
#        dpctl del-flows tcp:10.1.1.2;
#        sleep 20;
#        done
#        done
#done

table=1;
for flow_num in 1 10 25 50 75 99; do
    for try in `seq 1 20`; do
#        while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do
            sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
                /testbed/data/$type/mod_flow/config-$type-mod-flow.cfg \
                | tee /tmp/oflops.cfg
            /testbed/oflops/oflops -i /tmp/oflops.cfg
	    mv oflops.log /testbed/data/$type/mod_flow/wild/`printf "%05d" $flow_num`-$try-oflops.log;
	    dpctl del-flows tcp:10.1.1.2;
	    sleep 20;
#        done
    done
done

