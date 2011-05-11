#!/bin/bash 

type=netfpga;

for try in `seq 1 50`; do 
    for query_delay in 120000000 4000000 3000000 20000000 1000000 500000; do
	
	if [ ! -e /testbed/data/$type/interaction_delay_aggr/$query_delay ]; then
	    mkdir  /testbed/data/$type/interaction_delay_aggr/$query_delay;
	fi
	
	while [ ! -e oflops.log ]; do 
	    dpctl del-flows tcp:10.1.1.2;
	    sleep 20;
	    sed -e "s/%query_delay%/$query_delay/g" \
		/testbed/data/$type/interaction_delay/config-$type-interaction-test.cfg \
		> /tmp/oflops.cfg;
	    /testbed/oflops/oflops -i /tmp/oflops.cfg;
	done
	echo /testbed/data/$type/interaction_delay_aggr/$query_delay/$try-oflops.log;
	mv oflops.log /testbed/data/$type/interaction_delay_aggr/$query_delay/$try-oflops.log;
    done
done
# query_delay=120000000;
# for try in `seq 1 20`; do 
#     while [ ! -e oflops.log ]; do 
# 	dpctl del-flows tcp:10.1.1.2;
# 	sleep 20;
# 	sed -e "s/%query_delay%/$query_delay/g" \
# 	    /testbed/data/$type/interaction_delay/config-$type-interaction-test.cfg \
# 	    > /tmp/oflops.cfg;
# 	/testbed/oflops/oflops -i /tmp/oflops.cfg;
#     done
#     echo /testbed/data/$type/interaction_delay/no_stat/$try-oflops.log;
#     mv oflops.log /testbed/data/$type/interaction_delay/no_stat/$try-oflops.log;
# done

# query_delay=1000000;
# for try in `seq 1 20`; do 
#     while [ ! -e oflops.log ] ; do 
# 	dpctl del-flows tcp:10.1.1.2;
# 	sleep 20;
# 	sed -e "s/%query_delay%/$query_delay/g" \
# 	    /testbed/data/$type/interaction_delay/config-$type-interaction-test.cfg \
# 	    > /tmp/oflops.cfg
# 	/testbed/oflops/oflops -i /tmp/oflops.cfg
#     done
#     echo /testbed/data/$type/interaction_delay/stat/$try-oflops.log;
#     mv oflops.log /testbed/data/$type/interaction_delay/stat/$try-oflops.log;
# done
