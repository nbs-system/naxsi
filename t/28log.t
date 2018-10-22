#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

log_level('error');
#1.3 : +2 tests
plan tests => repeat_each() * (blocks() * 2 + (7));
no_root_location();
#no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1.0 : learning + block score, NAXSI_FMT
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
--- request eval
"GET /x,y?uuu=b,c"
--- error_code: 404
--- error_log eval
qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/x,y&vers=[^&]+&total_processed=1&total_blocked=1&config=learning&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu@
=== TEST 1.1 : learning + drop score, NAXSI_FMT
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" DROP;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request eval
"GET /x,y?uuu=b,c"
--- error_code: 412
--- error_log eval
qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/x,y&vers=[^&]+&total_processed=1&total_blocked=1&config=learning-drop&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu@
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
--- error_log eval
qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/x,y&vers=[^&]+&total_processed=1&total_blocked=1&config=block&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu, client: 127\.0\.0\.1, server: localhost,@
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
--- error_log eval
[qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=\/x,y&vers=[^&]+&total_processed=1&total_blocked=1&config=learning&cscore0=\$SQL&score0=8&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=uuu@,
qr@NAXSI_EXLOG: ip=127\.0\.0\.1&server=localhost&uri=%2Fx%2Cy&id=1015&zone=URL&var_name=&content=%2Fx%2Cy@,
qr@NAXSI_EXLOG: ip=127\.0\.0\.1&server=localhost&uri=%2Fx%2Cy&id=1015&zone=ARGS&var_name=uuu&content=b%2Cc@
]
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
--- error_log eval
qr@NAXSI_EXLOG: ip=127\.0\.0\.1&server=localhost&uri=%2Fx%2Cy&id=1015&zone=URL&var_name=&content=%2Fx%2Cy, client: 127\.0\.0\.1,@
--- no_error_log
NAXSI_FMT
=== TEST 1.6 : learning + block-score + naxsi_extensive_log, NAXSI_EXLOG only
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:foo" "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
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
[["GET /", "afoo"x256, "?f", "ufoo"x256, "=1", "Afoo"x256]]
--- error_code: 404
--- error_log eval
[ qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/afooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafoo&vers=[^&]+&total_processed=\d+&total_blocked=\d+&config=learning&cscore0=\$SQL&score0=3072&zone0=URL&id0=1015&var_name0=&seed_start=\d+,@ ,
qr@NAXSI_FMT: seed_end=\d+&zone1=ARGS&id1=1015&var_name1=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo&seed_start=\d+, @,
qr@NAXSI_FMT: seed_end=\d+&zone2=ARGS|NAME&id2=1015&var_name2=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo,@]
=== TEST 1.7 : learning + block-score + naxsi_extensive_log, NAXSI_EXLOG only
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:foo" "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
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
[["GET /", "afoo"x128, "?f", "ufoo"x256, "=1", "Afoo"x1024]]
--- error_code: 404
--- error_log eval
[ qr@NAXSI_FMT: ip=127\.0\.0\.1&server=localhost&uri=/afooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafooafoo&vers=[^&]+&total_processed=\d+&total_blocked=\d+&config=learning&cscore0=\$SQL&score0=5632&zone0=URL&id0=1015&var_name0=&zone1=ARGS&id1=1015&var_name1=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo&seed_start=\d+,@ ,
qr@NAXSI_FMT: seed_end=\d+&zone2=ARGS|NAME&id2=1015&var_name2=fufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufooufoo, @]
--- no_error_log
NAXSI_EXLOG


