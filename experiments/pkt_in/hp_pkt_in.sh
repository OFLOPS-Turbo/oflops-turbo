#!/bin/bash

ulimit -c 0

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [ -e measure.log ]; then
    rm measure.log;
fi

for try in `seq 1 20`; do 
    for pkt_size in 150 1500; do
	for flow_delay in 500 1000 1500 2500 5000 10000 25000 50000 75000 100000 250000 500000 750000 1000000; do
	     #check if the output directory is there
	     mkdir /testbed/data/hp/pkt_in/`printf "%05d" $pkt_size`/
	    
	    echo "param $try $pkt_size $flow_delay";
	    #generate configuration file
	    while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
		sed -e "s/%pkt_size%/$pkt_size/g"  -e "s/%flows_delay%/$flow_delay/g" \
		    /testbed/data/hp/pkt_in/config-hp-packet-in.cfg \
		    > /tmp/oflops.cfg
	    
                #rerun the experiment until we get proper results
		dpctl del-flows tcp:10.1.1.2:6000
		sleep 20;
		/testbed/oflops/oflops -i /tmp/oflops.cfg
	    done
		    
	    echo /testbed/data/hp/pkt_in/`printf "%05d" $pkt_size`/`printf "%07d" $flow_delay`-$try-oflops.log;
	    cp oflops.log /testbed/data/hp/pkt_in/`printf "%05d" $pkt_size`/`printf "%07d" $flow_delay`-$try-oflops.log;
	    rm oflops.log
	done
    done
done
