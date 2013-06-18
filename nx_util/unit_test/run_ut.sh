#!/bin/bash


for i in `ls 0* | grep -v .conf | grep -v .results` ; do 
    PY=$i; 
    echo "$i"
    nx_util.py -v0 -l $PY -o | grep "^Bas" > $PY".results.tmp"
    diff $PY".results" $PY".results.tmp"
    if [ "$?" != "0" ] ; then
	echo "fail on $PY";
	exit;
    else
	echo "success on $PY";
    fi
   #rm naxsi_sig
done
rm naxsi_sig*
rm 0*.tmp
#rm *.log
