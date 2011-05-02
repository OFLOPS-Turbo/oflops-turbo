#!/bin/bash

type=hp;

action_str[1]=vlan-vid;
action_str[2]=vlan-pcp;
action_str[3]=vlan-strip;
action_str[4]=dl-src;
action_str[5]=dl-dst;
action_str[6]=nw-src;
action_str[7]=nw-dst;
action_str[8]=nw-tos;
action_str[9]=tp-src;
action_str[a]=tp-dst;

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [ -e action_generic.log ]; then
    rm action_generic.log
fi


for try in `seq 1 20`; do 

    for action in 1/100 2/1 3/1 4/000000aabbcc 5/000000aabbcc 6/10101010 7/10101010 8/1 9/1000 a/1000; do 
	action_num=${action%/*};
	echo $action $action_num ${action_str[$action_num]};

	#create destination dir
	if [ ! -d /testbed/data/$type/action_delay/${action_str[$action_num]} ]; then
	    echo /testbed/data/$type/action_delay/${action_str[$action_num]};
	    mkdir /testbed/data/$type/action_delay/${action_str[$action_num]};
	fi

	#generate config file
	action_rep=` echo $action | sed -e "s/\\//\\\\\\\\\\\\//g" `;
	echo action_rep $action_rep;

	while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
	    sed -e "s/%action%/$action_rep/g"  \
		/testbed/data/$type/action_delay/config-$type-action-delay.cfg \
		> /tmp/oflops.cfg
	    dpctl del-flows ptcp:
	    sleep 20;
	    /testbed/oflops/oflops -i /tmp/oflops.cfg
	done
	
	echo /testbed/data/$type/action_delay/${action_str[$action_num]}/$try-oflops.log;
	mv oflops.log /testbed/data/$type/action_delay/${action_str[$action_num]}/$try-oflops.log;
	if [ -e action_generic.log ]; then
	    echo /testbed/data/$type/action_delay/${action_str[$action_num]}/$try-measure.log;
	    mv action_generic.log  /testbed/data/$type/action_delay/${action_str[$action_num]}/$try-action_generic.log;
	fi
    done 
done
