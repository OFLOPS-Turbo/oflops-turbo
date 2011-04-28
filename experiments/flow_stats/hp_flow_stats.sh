#!/bin/bash

ulimit -c unlimited

if [ -e oflops.log ]; then
    rm oflops.log;
fi

if [ -e measure.log ]; then
    rm measure.log;
fi

type=hp
table=0;
table_str=exact; 

# for try in `seq 1 10`; do 
#  for flow_num in 1 8 64 256 512 1024; do
#      for query_num in 1 8 64 256 512 1024; do
#  	for query_delay in 4000000 2000000 1000000 250000; do 
# 		if [ ! -d /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/ ]; then
# 		    mkdir /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/
# 	        fi
# 		if [ $query_num -gt $flow_num ]; then
# 			echo "skiping $query_num $flow_num $try $query_delay";
# 			continue;
# 		fi
# 		if [ "$try" -eq 1 ]; then
# 		    print=1;
# 		else 
# 		    print=0;
# 		fi 
		
# 		   # if [ "$table" -eq 1 ]; then
# 		   #     table_str=wild;
# 		   # else 
# 		   #     table_str=exact;
# 		   # fi 

# 		if [ ! -d /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str ]; then 
# 		    mkdir /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str
# 	        fi
# 		while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
		    
		
# 		sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
# 		    -e "s/%print%/$print/g" -e "s/%flows_query%/$query_num/g" \
#                     -e "s/%query_delay%/$query_delay/g" \
# 		       /testbed/data/$type/flow_stats/config-$type-flow-stats.cfg \
# 		    | tee /tmp/oflops.cfg
# 		    dpctl del-flows ptcp:
# 		    sleep 20;
# 		    /testbed/oflops/oflops -i /tmp/oflops.cfg
# 		done
# 		echo /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
# 		mv oflops.log /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
# 		if [ -e measure.log ]; then
# 		    echo /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
# 		    mv measure.log  /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
# 		fi
# 	    done
# 	done
#     done
# done

table=1;
table_str=wild;
for try in `seq 1 10`; do 
    for flow_num in 8 64 256 512 1024; do
	for query_num in 1 8 64 256 512 1024; do
 	    for query_delay in 4000000 2000000 1000000 250000; do 
		if [ ! -d /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/ ]; then
		    mkdir /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/
	        fi
		
		if [ $query_num -gt $flow_num ]; then
			echo "skiping $query_num $flow_num $try $query_delay";
			continue;
		fi

		if [ "$try" -eq 1 ]; then
		    print=1;
		else 
		    print=0;
		fi 
		   # if [ "$table" -eq 1 ]; then
		   #     table_str=wild;
		   # else 
		   #     table_str=exact;
		   # fi 

		if [ ! -d /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str ]; then 
		    mkdir /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str
	        fi
		
		while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "20" ]; do 
		    
		    sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
			-e "s/%print%/$print/g" -e "s/%flows_query%/$query_num/g" \
			-e "s/%query_delay%/$query_delay/g" \
			/testbed/data/$type/flow_stats/config-$type-flow-stats.cfg \
			| tee /tmp/oflops.cfg
		    dpctl del-flows ptcp:
		    sleep 20;
		    /testbed/oflops/oflops -i /tmp/oflops.cfg
		done
		mv oflops.log /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-oflops.log;
		if [ -e measure.log ]; then 
		    mv measure.log  /testbed/data/$type/flow_stats/`printf "%05d" $query_delay`/$table_str/`printf "%05d" $flow_num`-`printf "%05d" $query_num`-$try-measure.log;
		fi
	    done 
	done
    done
done
