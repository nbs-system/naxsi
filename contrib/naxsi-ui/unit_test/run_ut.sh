#!/bin/bash


for i in `ls 0* | grep -v .conf | grep -v .results` ; do 
    PY=$i; 
    echo "$i"
    python ../nx_intercept.py -c $PY".conf"  -l $PY 2>&1 > /dev/null;
    python ../nx_extract.py $PY".conf" 2>&1 > /dev/null &
    extract=$!
    echo "pid is $extract"
#    ps aux | grep nx_extract
    sleep 1;
    echo `wget --quiet --no-check-certificate --no-proxy --user=naxsi_web --password=test 127.0.0.1:8081/get_rules -O - | grep -v "^#"` > $PY".results.tmp"
    echo `wget --quiet --no-check-certificate --no-proxy --user=naxsi_web --password=test 127.0.0.1:8081/get_rules -O - | grep -v "^#"` | diff $PY".results" -
    if [ "$?" != "0" ] ; then
	kill -9 $extract 2>&1 > /dev/null
	echo "fail on $PY";
	exit;
    else
	kill -9 $extract 2>&1 > /dev/null
	echo "success on $PY";
    fi
done
rm naxsi_sig*
rm 0*.tmp
