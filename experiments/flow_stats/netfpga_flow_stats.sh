#!/bin/bash

ulimit -c 0

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [ -e measure.log ]; then
    rm measure.log;
fi

table=0;
table_str=exact;
for flow_num in 1024; do
    for query_num in 1024; do
 	for query_delay in 4000000 2000000 1000000 500000 250000; do 
 	    for try in `seq 1 50`; do 
		ssh cr409@stix.cl.cam.ac.uk mkdir /auto/homes/cr409/anfs/oflops_data/netfpga/flow_stats/`printf "%05d" $query_delay`/
		if [ $query_num -gt $flow_num ]; then
		    echo "skiping $query_num $flow_num $try $query_delay";
		    continue;
		fi
		if [ "$try" -eq 1 ]; then
		    print=1;
		else 
		    print=0;
		fi
		ssh cr409@stix.cl.cam.ac.uk mkdir /auto/homes/cr409/anfs/oflops_data/netfpga/flow_stats/`printf "%05d" $query_delay`/$table_str
	   
		sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
		    -e "s/%print%/$print/g" -e "s/%flows_query%/$query_num/g" \
		    -e "s/%query_delay%/$query_delay/g" \
		    /testbed/data/netfpga/flow_stats/config-netfpga-flow-stats.cfg \
		    > /tmp/oflops.cfg

		echo "param $table_str $query_num $flow_num $try $query_delay";
		while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
		    dpctl del-flows tcp:10.1.1.2 #ptcp:
		    sleep 20;
		    /testbed/oflops/oflops -i /tmp/oflops.cfg
		done 
		echo cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/netfpga/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
		scp oflops.log cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/netfpga/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
		rm oflops.log
		if [ -e measure.log ]; then
		    echo /testbed/data/netfpga/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
		    scp measure.log  cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/netfpga/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
		    rm measure.log
		fi
	    done
	done
    done
done
