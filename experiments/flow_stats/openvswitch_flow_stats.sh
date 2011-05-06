#!/bin/bash

ulimit -c 0

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [ -e measure.log ]; then
    rm measure.log;
fi

for try in `seq 1 5`; do 
    for flow_num in 1 8 64 256 512 1024; do
	for query_num in 1 8 64 256 512 1024; do
	    for query_delay in 4000000 1000000 250000; do 
		for table in 0 1; do 

		    #check if the output directory is there
		    ssh cr409@stix.cl.cam.ac.uk mkdir /auto/homes/cr409/anfs/oflops_data/openvswitch/flow_stats/`printf "%05d" $query_delay`/

		    #skip any test with query num larger that the flow number
		    if [ $query_num -gt $flow_num ]; then
                        echo "skiping $query_num $flow_num $try $query_delay";
			continue;
		    fi
		    
		    #print detailed information about the packets 
		    if [ "$try" -eq 1 ]; then
			print=1;
		    else 
			print=0;
		    fi 
		    
		    #define if the flow is wild card or normal
		    if [ "$table" -eq 1 ]; then
		        table_str=wild;
		    else 
			table_str=exact;
		    fi 
		    
		    #check if the output directory is there 
		    if [ ! -d /testbed/data/openvswitch/flow_stats/`printf "%05d" $query_delay`/$table_str ]; then 
			 ssh cr409@stix.cl.cam.ac.uk mkdir /auto/homes/cr409/anfs/oflops_data/openvswitch/flow_stats/`printf "%05d" $query_delay`/$table_str
		    fi
		    
		    echo "param $table_str $query_num $flow_num $try $query_delay";
		    #generate configuration file
		    sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
			-e "s/%print%/$print/g" -e "s/%flows_query%/$query_num/g" \
			-e "s/%query_delay%/$query_delay/g" \
			/testbed/data/openvswitch/flow_stats/config-openvswitch-flow-stats.cfg \
			> /tmp/oflops.cfg
		    
		    #rerun the experiment until we get proper results
		    while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
			dpctl del-flows tcp:192.168.1.2   
			sleep 20;
			/testbed/oflops/oflops -i /tmp/oflops.cfg
		    done
		    
		    
		    echo /testbed/data/openvswitch/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
		     scp oflops.log   cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/openvswitch/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
		     rm oflops.log
		    #if there is a detailed packet output, move it to dest dir
		    if [ -e measure.log ]; then
			echo /testbed/data/openvswitch/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
			scp measure.log  cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/openvswitch/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
			rm measure.log
		    fi
		done
	    done
	done
    done
done
