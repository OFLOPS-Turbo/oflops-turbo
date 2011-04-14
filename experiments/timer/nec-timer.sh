#!/bin/bash

type=nec

table=0;

if [ ! -e  /testbed/data/$type/timer/ ]; then
    mkdir  /testbed/data/$type/timer/;
fi

if [ ! -e  /testbed/data/$type/timer/exact/ ]; then
    mkdir  /testbed/data/$type/timer/exact/;
fi

for i in `seq 1 20`; do
    for flow_num in 1 10 50 `seq 100 100 500` 750 1000; do
        sed -e "s/%table%/$table/g"  -e "s/%flows%/$flow_num/g" \
            /testbed/data/$type/timer/config-$type-timer.cfg \
            | tee /tmp/oflops.cfg
        while [ ! -e oflops.log ] ||  [ "`wc -l oflops.log | cut -d \  -f 1 `" -lt "50" ]; do
            /testbed/oflops/oflops -i /tmp/oflops.cfg
        done
        mv oflops.log /testbed/data/$type/timer/exact/`printf "%05d" $flow_num`-$try-oflops.log;
        dpctl del-flows ptcp:;
        sleep 20;
        done
done