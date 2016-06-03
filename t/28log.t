#vi:filetype=perl

<<<<<<< HEAD
use lib 'lib';
use Test::Nginx::Socket;

log_level('error');
#1.3 : +2 tests
plan tests => repeat_each() * (blocks() * 2 + (7));
no_root_location();
#no_long_string();
=======
# Test naxsi logging mechanism
# !! all without core_rules to avoid breaking tests in the future
# TEST 1.0 : learning + non-block score, no NAXSI_FMT
# TEST 1.1 : learning + block score, NAXSI_FMT
# TEST 1.2 : no-learning + block score, NAXSI_FMT
# TEST 1.3 : learning + block score + naxsi_extensive_log, NAXSI_EXLOG and NAXSI_FMT
# TEST 1.4 : learning + no-block score + naxsi_extensive_log, NAXSI_EXLOG only
#!TEST 1.5 : learning + drop rule : NAXSI_FMT
#!TEST 1.6 : learning + block-score in multi-line generated

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(3);

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SLEEP} = 1;
>>>>>>> travis try again
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
<<<<<<< HEAD
=== TEST 1.0 : learning + block score, NAXSI_FMT
=======
=== TEST 1.0 : learning + non-block score, no NAXSI_FMT
>>>>>>> travis try again
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
<<<<<<< HEAD
--- request eval
"GET /x,y?uuu=b,c"
--- error_code: 404
--- error_log eval
qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/x,y&learning=1&vers=0.55rc2&total_processed=1&total_blocked=1&block=1&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu@
=======
--- request
GET /x,y?uuu=b,c
--- error_code: 404
=== TEST 1.1 : learning + block score, NAXSI_FMT
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /x,y?uuu=b,c
--- error_code: 404
--- grep_error_log eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/x,y&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"']
--- grep_error_log_out eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/x,y&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"']
>>>>>>> travis try again
=== TEST 1.2 : no-learning + block score, NAXSI_FMT
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /x,y?uuu=b,c
--- error_code: 412
<<<<<<< HEAD
--- error_log eval
qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/x,y&learning=0&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127\.0\.0\.1, server: localhost,@
=======
--- grep_error_log eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/x,y&learning=0&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"']
--- grep_error_log_out eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/x,y&learning=0&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"']
>>>>>>> travis try again
=== TEST 1.3 : learning + block score + naxsi_extensive_log, NAXSI_EXLOG and NAXSI_FMT
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /x,y?uuu=b,c
--- error_code: 404
<<<<<<< HEAD
--- error_log eval
[qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/x,y&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu@,
qr@NAXSI_EXLOG: ip=127\.0\.0\.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y,@,
qr@NAXSI_EXLOG: ip=127\.0\.0\.1&server=localhost&uri=/x,y&id=1015&zone=ARGS&var_name=uuu&content=b,c@
]
=======
--- grep_error_log eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/x,y&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=ARGS&var_name=uuu&content=b,c, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"']
--- grep_error_log_out eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/x,y&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=ARGS&var_name=uuu&content=b,c, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=b,c HTTP/1.1", host: "localhost"']
=== TEST 1.4 : learning + no-block score + naxsi_extensive_log, NAXSI_EXLOG only
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /x,y?uuu=bc
--- error_code: 404
--- grep_error_log eval
['^NAXSI_FMT', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=bc HTTP/1.1", host: "localhost"']
--- grep_error_log_out eval
['^NAXSI_FMT', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=bc HTTP/1.1", host: "localhost"']
>>>>>>> travis try again
=== TEST 1.4 : learning + no-block score + naxsi_extensive_log, NAXSI_EXLOG only
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /x,y?uuu=bc
--- error_code: 404
<<<<<<< HEAD
--- error_log eval
qr@NAXSI_EXLOG: ip=127\.0\.0\.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127\.0\.0\.1,@
--- no_error_log
NAXSI_FMT
=======
--- grep_error_log eval
['^NAXSI_FMT', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=bc HTTP/1.1", host: "localhost"']
--- grep_error_log_out eval
['^NAXSI_FMT', 'NAXSI_EXLOG: ip=127.0.0.1&server=localhost&uri=/x,y&id=1015&zone=URL&var_name=&content=/x,y, client: 127.0.0.1, server: localhost, request: "GET /x,y?uuu=bc HTTP/1.1", host: "localhost"']
>>>>>>> travis try again
=== TEST 1.6 : learning + block-score + naxsi_extensive_log, NAXSI_EXLOG only
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
<<<<<<< HEAD
MainRule "str:foo" "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
=======
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
>>>>>>> travis try again
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request eval
<<<<<<< HEAD
[["GET /", "afoo"x256, "?f", "ufoo"x256, "=1", "Afoo"x256]]
--- error_code: 404
--- error_log eval
[ qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/afooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafoo&learning=\d+&vers=[^&]+&total_processed=\d+&total_blocked=\d+&block=1&cscore0=\$SQL&score0=3072&zone0=URL&id0=1015&var_name0=&seed_start=\d+,@ ,
qr@NAXSI_FMT: seed_end=\d+&zone1=ARGS&id1=1015&var_name1=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo&seed_start=\d+, @,
qr@NAXSI_FMT: seed_end=\d+&zone2=ARGS|NAME&id2=1015&var_name2=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo,@]
=======
[["GET /", "a,"x1024, "?f", "u,"x1024, "=1", "A,"x1024]]
--- error_code: 404
--- grep_error_log eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,&seed_start=\d, client: 127.0.0.1, server: localhost', 'NAXSI_FMT: seed_end=\d&cscore0=$SQL&score0=12288&zone0=URL&id0=1015&var_name0=&seed_start=\d, client: 127.0.0.1, server: localhost, request: ', 'NAXSI_FMT: seed_end=\d&zone1=ARGS&id1=1015&var_name1=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u&seed_start=\d, client: 127.0.0.1, server: localhost, request',
'NAXSI_FMT: seed_end=\d&zone2=ARGS|NAME&id2=1015&var_name2=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u, client: 127.0.0.1, server: localhost, request: ']
--- grep_error_log_out eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,&seed_start=\d, client: 127.0.0.1, server: localhost', 'NAXSI_FMT: seed_end=\d&cscore0=$SQL&score0=12288&zone0=URL&id0=1015&var_name0=&seed_start=\d, client: 127.0.0.1, server: localhost, request: ', 'NAXSI_FMT: seed_end=\d&zone1=ARGS&id1=1015&var_name1=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u&seed_start=\d, client: 127.0.0.1, server: localhost, request',
'NAXSI_FMT: seed_end=\d&zone2=ARGS|NAME&id2=1015&var_name2=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u, client: 127.0.0.1, server: localhost, request: ']
>>>>>>> travis try again
=== TEST 1.7 : learning + block-score + naxsi_extensive_log, NAXSI_EXLOG only
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
<<<<<<< HEAD
MainRule "str:foo" "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
=======
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
>>>>>>> travis try again
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request eval
<<<<<<< HEAD
[["GET /", "afoo"x128, "?f", "ufoo"x256, "=1", "Afoo"x1024]]
--- error_code: 404
--- error_log eval
[ qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/afooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafoo&learning=1&vers=[^&]+&total_processed=\d+&total_blocked=\d+&block=1&cscore0=\$SQL&score0=5632&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo&seed_start=\d+,@ ,
qr@NAXSI_FMT: seed_end=\d+&zone2=ARGS|NAME&id2=1015&var_name2=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo, @]
--- no_error_log
NAXSI_EXLOG
=======
[["GET /", "a,"x512, "?f", "u,"x1024, "=1", "A,"x1024]]
--- error_code: 404
--- grep_error_log eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=10240&zone0=URL&id0=1015&var_name0=&seed_start=\d, client: 127.0.0.1, server: localhost, request',
'NAXSI_FMT: seed_end=\d&zone1=ARGS&id1=1015&var_name1=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u&seed_start=\d, client: 127.0.0.1, server: localhost',
'NAXSI_FMT: seed_end=\d&zone2=ARGS|NAME&id2=1015&var_name2=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,, client: 127.0.0.1, server: localhost, request: ']
--- grep_error_log_out eval
['NAXSI_FMT: ip=127.0.0.1&server=localhost&uri=/a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,&learning=1&vers=[^&]+&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=10240&zone0=URL&id0=1015&var_name0=&seed_start=\d, client: 127.0.0.1, server: localhost, request',
'NAXSI_FMT: seed_end=\d&zone1=ARGS&id1=1015&var_name1=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u&seed_start=\d, client: 127.0.0.1, server: localhost',
'NAXSI_FMT: seed_end=\d&zone2=ARGS|NAME&id2=1015&var_name2=fu,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,, client: 127.0.0.1, server: localhost, request: ']



>>>>>>> travis try again


