#!/bin/bash 

type=netfpga;

rm oflops.log;

for try in `seq 1 1`; do 
    for flows in 50 100 300 500 700 1000; do
	
	while [ ! -e oflops.log ]; do 
	    dpctl del-flows tcp:10.1.1.2;
	    sleep 20;
	    sed -e "s/%flows%/$flows/g" \
		/testbed/data/$type/interaction_delay_2/config-$type-interaction-test.cfg \
		> /tmp/oflops.cfg;
	    /testbed/oflops/oflops -i /tmp/oflops.cfg;
	done
	echo /testbed/data/$type/interaction_delay_2/$flows-$try-oflops.log;
	mv oflops.log /testbed/data/$type/interaction_test_2/$flows-$try-oflops.log;
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
