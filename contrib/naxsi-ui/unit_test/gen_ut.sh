#!/bin/bash

SAMPLE_REQ="2012/02/22 10:05:45 [error] 32117#0: *32 NAXSI_FMT: ip=<IP>&server=<SRV>&uri=<URI>&total_processed=<TOT_PROC>&total_blocked=<TOT_BLOC>"
APPEND="&zone0=<ZONE>&id0=<ID>&var_name0=<VAR_NAME>"
CLOSING=", client: 82.234.123.117, server: blog.memze.ro, request: \"GET / HTTP/1.1\", host: \"blog.memze.ro\""
NB_LINES=100

function randstr() {
  [ "$2" == "0" ] && CHAR="[:alnum:]" || CHAR="[:graph:]"
    cat /dev/urandom | tr -cd "$CHAR" | head -c ${1:-32}
    echo
}

#IP;SRV;URI;TOT_PROC;TOT_BLOC;ZONE;ID;VAR_NAME
function do_replace {
    echo -n $SAMPLE_REQ | sed -e "s@<IP>@$1@g;s@<SRV>@$2@g;s@<URI>@$3@g;s@<TOT_PROC>@$4@g;s@<TOT_BLOC>@$5@g"
    echo -n $APPEND | sed -e "s@<ZONE>@$6@g;s@<ID>@$7@g;s@<VAR_NAME>@$8@g"
    echo $CLOSING
}

function unpredictable_id {
    
    for i in `seq 1 100` ; do
	url="/comment_post.php"
	arg_name="foobar"
	do_replace "1.1.1.254" "foo.net" "/"$url "1" "0" "ARGS" $(( ($RANDOM % 1000) + 1000))  $arg_name
    done;
}

function unpredictable_url {
    
    for i in `seq 1 100` ; do
	url=`randstr 10 0`
	arg_name="foobar"
	do_replace "1.1.1.254" "foo.net" "/"$url "1" "0" "ARGS" 1001  $arg_name
    done;
}

function unpredictable_argname {
    
    for i in `seq 1 100` ; do
	arg_name=`randstr 10 0`
	url="/foobar"
	do_replace "1.1.1.254" "foo.net" "/"$url "1" "0" "ARGS" 1001  $arg_name
    done;
}

function unpredictable_nothing {
    
    for i in `seq 1 100` ; do
	arg_name="vulnarg"
	url="/foobar"
	do_replace "1.1.1.254" "foo.net" "/"$url "1" "0" "ARGS" 1001  $arg_name
    done;
}



#do_replace "1.1.1.1" "foo.net" "/bar" "1" "0" "ARGS" "1000" "vuln_arg"
#one_exc_many_peer_diff_url
#100_exc_one_peer
unpredictable_nothing

