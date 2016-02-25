#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(3);

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 2 : Check libinjection_xss is disabled by default
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?x=a' onmouseover='alert(1) HTTP/1.0

"
--- error_code: 200


=== TEST 2.1 : Check libinjection_xss can be enabled
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?x=1' OR '1'='1 HTTP/1.0

"
--- error_code: 200


=== TEST 3.1 : Check libinjection_sql can be enabled
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?x=1' OR '1'='1 HTTP/1.0

"
--- error_code: 412


=== TEST 3.2 : Check libinjection_sql can be enabled and dyn disabled
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?x=1' OR '1'='1 HTTP/1.0

"
--- error_code: 200
=== TEST 3.3 : Check libinjection_sql can be disabled and dyn enabled
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?x=1' OR '1'='1 HTTP/1.0

"
--- error_code: 412
=== TEST 4.0 : whitelist libinjection_sql
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?x=1' OR '1'='1 HTTP/1.0

"
--- error_code: 200
=== TEST 4.1 : whitelist libinjection_xss
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
"GET /?a' UNION SELECT 1,1=1 HTTP/1.0

"
--- error_code: 412


=== TEST 4.3.2 : whitelist fail libinjection_xss (|NAME)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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


