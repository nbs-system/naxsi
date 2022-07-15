#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1.0: Basic GET request, with allow rule (useless, just for coverage. ALLOW should be killed)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:ARGS" "s:$TEST:42";
#MainRule id:4242 "str:XXX" "s:$SQL:8" "mz:ARGS";
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /?a=ratataXXX
--- error_code: 200
=== TEST 1.1: Basic GET request, with global score increase
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:ARGS" "s:42";
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /?a=ratataXXX
--- error_code: 200
=== TEST 1.2: rule on headers
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 SecRulesEnabled;
	 BasicRule id:4241 "str:ratata" "mz:HEADERS" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- more_headers
headertest: ratata
--- request
GET /?a=XXX
--- error_code: 412
=== TEST 1.2: extensive log while targeting name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
	 SecRulesEnabled;
	 LearningMode;
	 BasicRule id:4241 "str:ratata" "mz:ARGS" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /?ratata=tututu
--- error_code: 200
=== TEST 1.2: extensive log while targeting name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
	 SecRulesEnabled;
	 LearningMode;
	 BasicRule id:4241 "str:ratata" "mz:ARGS" "s:LOG";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /?ratata=tututu
--- error_code: 200
=== TEST 1.3: rule on url
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
	 SecRulesEnabled;
	 BasicRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /ratata?x=tututu
--- error_code: 412
=== TEST 1.4: add post action as dynamic flag
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
set $naxsi_flag_post_acton 1;
location / {
	 SecRulesEnabled;
	 BasicRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /ratata?x=tututu
--- error_code: 412
=== TEST 1.5.0: HEADER_VAR_X
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
MainRule id:4241 "str:ratata" "mz:$HEADERS_VAR_X:ruuu" "s:BLOCK";
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
set $naxsi_flag_post_acton 1;
location / {
	 SecRulesEnabled;
#	 BasicRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- more_headers
ruuu: ratata1
--- request
GET /ratata?x=tututu
--- error_code: 412
=== TEST 1.5.1: HEADER_VAR_X
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
MainRule id:4241 "str:ratata" "mz:$HEADERS_VAR_X:ruuu|$URL_X:^/fufu" "s:BLOCK";
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
set $naxsi_flag_post_acton 1;
location / {
	 SecRulesEnabled;
#	 BasicRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- more_headers
ruuu: ratata1
--- request
GET /fufu?x=tututu
--- error_code: 412
=== TEST 1.5.2: HEADER_VAR_X
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
MainRule id:4241 "str:ratata" "mz:$HEADERS_VAR_X:ruuu|$URL_X:^/fufu" "s:BLOCK";
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
set $naxsi_flag_post_acton 1;
location / {
	 SecRulesEnabled;
#	 BasicRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- more_headers
ruuu: ratata1
--- request
GET /fuf?x=tututu
--- error_code: 404
=== TEST 1.6.0: URL + URL wl
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
MainRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
set $naxsi_flag_post_acton 1;
location / {
	 SecRulesEnabled;
	 BasicRule wl:4241 "mz:URL";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /ratata
--- error_code: 404
=== TEST 1.6.1: URL + URL wl
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
MainRule id:4241 "str:ratata" "mz:URL" "s:BLOCK";
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
set $naxsi_flag_post_acton 1;
location / {
	 SecRulesEnabled;
	 BasicRule wl:4241 "mz:BODY";
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TEST >= 8" ALLOW;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /ratata
--- error_code: 412





