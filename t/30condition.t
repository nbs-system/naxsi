# 
# vi:filetype=text

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== WL TEST 1.0: Check two rules : true and true
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word1=word1&word2=word2
--- error_code: 412

=== WL TEST 1.1: Check two rules : true and false
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word1=word1&word=word2
--- error_code: 200

=== WL TEST 1.2: Check two rules : false and true
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word=word1&word2=word2
--- error_code: 200

=== WL TEST 1.3: Check two rules : false and false
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word=word
--- error_code: 200

=== WL TEST 2.1: Check three rules : true and true and true
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;
MainRule "msg:word3" "str:word3" "mz:$ARGS_VAR:word3" "s:$WORD3:1" id:9900003;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" AND;
	 CheckRule "$WORD2 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word1=word1&word2=word2&word3=word3
--- error_code: 412

=== WL TEST 2.2: Check three rules : false and true and true
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;
MainRule "msg:word3" "str:word3" "mz:$ARGS_VAR:word3" "s:$WORD3:1" id:9900003;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" AND;
	 CheckRule "$WORD3 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word=word1&word2=word2&word3=word3
--- error_code: 200

=== WL TEST 2.3: Check three rules : true and false and true
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;
MainRule "msg:word3" "str:word3" "mz:$ARGS_VAR:word3" "s:$WORD3:1" id:9900003;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" AND;
	 CheckRule "$WORD3 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word1=word1&word=word2&word3=word3
--- error_code: 200

=== WL TEST 2.4: Check three rules : true and true and false
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "msg:word1" "str:word1" "mz:$ARGS_VAR:word1" "s:$WORD1:1" id:9900001;
MainRule "msg:word2" "str:word2" "mz:$ARGS_VAR:word2" "s:$WORD2:1" id:9900002;
MainRule "msg:word3" "str:word3" "mz:$ARGS_VAR:word3" "s:$WORD3:1" id:9900003;

--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$WORD1 >= 1" AND;
	 CheckRule "$WORD2 >= 1" AND;
	 CheckRule "$WORD3 >= 1" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?word1=word1&word2=word2&word=word3
--- error_code: 200

