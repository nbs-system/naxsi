#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 2 : Check libinjection_xss is disabled by default
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=a'%20onmouseover='alert(1) HTTP/1.0

"
--- error_code: 200


=== TEST 2.1 : Check libinjection_xss can be enabled
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
         SecRulesEnabled;
	 LibInjectionXss;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=<script>alert(1)</script> HTTP/1.0

"
--- error_code: 412


=== TEST 2.2 : Check libinjection_xss can be enabled and dyn disabled
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_xss 0;
location / {
         SecRulesEnabled;
	 LibInjectionXss;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=<script>alert(1)</script> HTTP/1.0

"
--- error_code: 200


=== TEST 2.3 : Check libinjection_xss can be disabled and dyn enabled
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_xss 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=<script>alert(1)</script> HTTP/1.0

"
--- error_code: 412

=== TEST 3 : Check libinjection_sql is disabled by default
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=1'%20OR%20'1'='1 HTTP/1.0

"
--- error_code: 200


=== TEST 3.1 : Check libinjection_sql can be enabled
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
         SecRulesEnabled;
	 LibInjectionSql;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=1'%20OR%20'1'='1 HTTP/1.0

"
--- error_code: 412


=== TEST 3.2 : Check libinjection_sql can be enabled and dyn disabled
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_sql 0;
location / {
         SecRulesEnabled;
	 LibInjectionSql;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=1'%20OR%20'1'='1 HTTP/1.0

"
--- error_code: 200
=== TEST 3.3 : Check libinjection_sql can be disabled and dyn enabled
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_sql 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
        # return 412;
}
--- raw_request eval
"GET /?x=1'%20OR%20'1'='1 HTTP/1.0

"
--- error_code: 412
=== TEST 4.0 : whitelist libinjection_sql
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_sql 1;
location / {
	 BasicRule wl:17 "mz:$URL:/|$ARGS_VAR:x";
         SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?x=1'%20OR%20'1'='1 HTTP/1.0

"
--- error_code: 200
=== TEST 4.1 : whitelist libinjection_xss
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_xss 1;
location / {
	 BasicRule wl:18 "mz:$URL:/|$ARGS_VAR:x";
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?x=<script>alert(1)</script> HTTP/1.0

"
--- error_code: 200

=== TEST 4.2 : whitelist libinjection_xss (|NAME)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_xss 1;
location / {
	 BasicRule wl:18 "mz:$URL:/|ARGS|NAME";
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?<script>alert(1)</script>=1 HTTP/1.0

"
--- error_code: 200


=== TEST 4.3 : whitelist libinjection_sql (|NAME)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_sql 1;
location / {
	 BasicRule wl:17 "mz:$URL:/|ARGS|NAME";
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?a/**/UNION+SELECT+1,1=1 HTTP/1.0

"
--- error_code: 200


=== TEST 4.3.1 : whitelist fail libinjection_sql (|NAME)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_sql 1;
location / {
	 BasicRule wl:17 "mz:$URL:/x|ARGS|NAME";
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?a'%20UNION%20SELECT%201,1=1 HTTP/1.0

"
--- error_code: 412


=== TEST 4.3.2 : whitelist fail libinjection_xss (|NAME)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_flag_libinjection_xss 1;
location / {
	 BasicRule wl:18 "mz:$URL:/x|ARGS|NAME";
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?a><script>alert(1)</script>=1 HTTP/1.0

"
--- error_code: 412


