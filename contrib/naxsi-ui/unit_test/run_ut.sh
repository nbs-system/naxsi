#!/bin/bash


for i in `ls 0* | grep -v .conf | grep -v .results` ; do 
    PY=$i; 
    echo "$i"
    python ../nx_intercept.py -c naxsi-ui.conf  -l $PY 2>&1 > /dev/null;
    python ../nx_extract.py -c naxsi-ui.conf -o | grep  "^Bas" > $PY".results.tmp"
   sleep 1;
 
   diff $PY".results" $PY".results.tmp"
   if [ "$?" != "0" ] ; then
       echo "fail on $PY";
       exit;
   else
       echo "success on $PY";
   fi
   rm naxsi_sig
done
rm naxsi_sig*
rm 0*.tmp
rm *.log
