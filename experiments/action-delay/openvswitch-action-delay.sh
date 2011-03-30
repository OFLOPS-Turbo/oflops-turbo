#!/bin/bash

action_str[1]=vlan-vid
action_str[2]=vlan-pcp
action_str[3]=vlan-strip
action_str[4]=dl-src
action_str[5]=dl-dst
action_str[6]=nw-src
action_str[7]=nw-dst
action_str[8]=nw-tos
action_str[9]=tp-src
action_str[a]=tp-dst

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [-e action_generic.log]; then
    rm action_generic.log
fi


for try in `seq 1 5`; do 

    for action in 1/100 2/1 3/1 4/000000aabbcc 5/000000aabbcc 6/10101010 7/10101010 8/1 9/1000 a/1000; do 
	action_num=${action%/*};
	echo $action $action_num ${action_str[$action_num]};

	#create destination dir
	ssh cr409@stix.cl.cam.ac.uk mkdir /auto/homes/cr409/anfs/oflops_data/openvswitch/action_delay/${action_str[$action_num]};
	
	#generate config file
	action_rep=` echo $action | sed -e "s/\\//\\\\\\\\\\\\//g" `;
	echo action_rep $action_rep;

	sed -e "s/%action%/$action_rep/g"  \
	    /testbed/data/openvswitch/action_delay/config-openvswitch-action-delay.cfg \
	    > /tmp/oflops.cfg

	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	    dpctl del-flows tcp:192.168.1.2
	    sleep 20;
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	
	echo cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/openvswitch/action_delay/${action_str[$action_num]}/$try-oflops.log;
	scp oflops.log cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/openvswitch/action_delay/${action_str[$action_num]}/$try-oflops.log;
	rm oflops.log; 
	if [ -e action_generic.log ]; then
	    echo /testbed/data/openvswitch/action_delay/${action_str[$action_num]}/$try-measure.log;
	    scp action_generic.log  cr409@stix.cl.cam.ac.uk:/auto/homes/cr409/anfs/oflops_data/openvswitch/action_delay/${action_str[$action_num]}/$try-action_generic.log;
	    rm action_generic.log
	fi
	
    done 
done