#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1 : Enable libinjection s:DROP on named var
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "d:libinj_xss" "s:DROP" "mz:$ARGS_VAR:ruuu" id:41231;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?ruuu=a'%20onmouseover='alert(1) HTTP/1.0

"
--- error_code: 412
=== TEST 1.1 : Enable libinjection s:DROP on (bad) named var
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "d:libinj_xss" "s:DROP" "mz:$ARGS_VAR:ruuuu" id:41231;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?ruuu=a'%20onmouseover='alert(1) HTTP/1.0

"
--- error_code: 200
=== TEST 1.2 : Enable libinjection s:DROP on (bad) named var
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "d:libinj_xss" "s:DROP" "mz:$ARGS_VAR:ruu" id:41231;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?ruuu=a'%20onmouseover='alert(1) HTTP/1.0

"
--- error_code: 200
=== TEST 2.1 : Enable libinjection s:$FOOBAR on named var
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "d:libinj_xss" "s:$FOOBAR:8" "mz:$ARGS_VAR_X:^fuu[0-9]+$" id:41231;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
	 CheckRule "$FOOBAR >= 8" DROP;
         DeniedUrl "/RequestDenied";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /?fuu4242424=a'%20onmouseover='alert(1) HTTP/1.0

"
--- error_code: 412

=== TEST 3.0 : Enable libinjection (sql) s:DROP on named var+url
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "d:libinj_sql" "s:$FOOBAR:8" "mz:$ARGS_VAR_X:^fuu[0-9]+$|$URL_X:^/foobar/$" id:41231;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
	 CheckRule "$FOOBAR >= 8" DROP;
         DeniedUrl "/RequestDenied";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /foobar/?fuu4242424=1'%20OR%20'1'='1 HTTP/1.0

"
--- error_code: 412
=== TEST 3.0 : Enable libinjection (sql) s:DROP on named var+url (not a valid sqli)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "d:libinj_sql" "s:$FOOBAR:8" "mz:$ARGS_VAR_X:^fuu[0-9]+$|$URL_X:^/foobar/$" id:41231;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
	 CheckRule "$FOOBAR >= 8" DROP;
         DeniedUrl "/RequestDenied";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- raw_request eval
"GET /foobar/?fuu4242424=1'%20OR%20\"1\"= HTTP/1.0

"
--- error_code: 404

