#!/bin/bash

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [ -e action_generic.log ]; then
    rm action_generic.log
fi


for try in `seq 1 10`; do 
    count=1;
    action_list='1/100';

    for action in 2/1 3/1 4/000000aabbcc 5/000000aabbcc 6/10101010 7/10101010 8/1 9/1000 a/1000; do 
	action_list=$action_list','$action;
	count=$((count+1));
	action_num=${action%/*};
	echo $count $action_list;
	
	#create destination dir
	ssh cr409@stix.cl.cam.ac.uk mkdir /auto/homes/cr409/anfs/oflops_data/netfpga/action_delay/`printf "%saction" $count`/;
	
	#generate config file
	action_rep=` echo $action_list | sed -e "s/\\//\\\\\\\\\\\\//g" `;
	echo action_rep $action_rep;
	
	print=0;
	if [ $try == 1 ]; then
	    print=1;
	fi
	
	sed -e "s/%action%/$action_rep/g" -e "s/%print%/$print/g"  \
	    /testbed/data/netfpga/action_delay/config-netfpga-action-delay.cfg \
	    > /tmp/oflops.cfg
	
	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	    dpctl del-flows tcp:10.1.1.2 #ptcp:
	    sleep 20;
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	
	echo cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/netfpga/action_delay/`printf "%saction" $count`/$try-oflops.log;
	scp oflops.log cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/netfpga/action_delay/`printf "%saction" $count`/$try-oflops.log;
	rm oflops.log; 
	if [ -e action_generic.log ]; then
	    echo /testbed/data/netfpga/action_delay/`printf "%saction" $count`/$try-measure.log;
	    scp action_generic.log  cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/netfpga/action_delay/`printf "%saction" $count`/$try-action_generic.log;
	    rm action_generic.log
	fi
	
    done 
done
