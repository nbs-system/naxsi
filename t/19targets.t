use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== ID TEST 1.0: Drop rule without learning
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:DROP" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412

=== ID TEST 1.1: whitelisted drop rule without learning
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:DROP" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
	 BasicRule wl:1999 "mz:ARGS";
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 200

=== ID TEST 1.2: bad whitelisted drop rule without learning
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:DROP" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
	 BasicRule wl:1999 "mz:URL";
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412

=== ID TEST 1.3: drop rule with learning
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:DROP" id:1999;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412



=== ID TEST 1.4: drop rule with learning + correct whitelist
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:DROP" id:1999;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
	 BasicRule wl:1999 "mz:$ARGS_VAR:bla";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 200


=== ID TEST 1.5: drop rule with learning + incorrect whitelist
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:DROP" id:1999;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
	 BasicRule wl:1999 "mz:$ARGS_VAR:bla|$URL:/x";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412



=== ID TEST 2.0: drop checkrule
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO >= 8" DROP;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412

=== ID TEST 2.1: drop checkrule, with whitelisted rule
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO >= 8" DROP;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR_X:^bla$";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 200
=== ID TEST 2.2: drop checkrule, with failed whitelisted rule
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO >= 8" DROP;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR_X:^bla1";
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412



=== ID TEST 3.0: <= checkrule (why not dude)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO <= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412
=== ID TEST 3.1: <= checkrule : Is useless, as score will go through value 8 before reaching 16, thus the checkrule will be applied
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO <= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999&blu=1999
--- error_code: 412
=== ID TEST 3.2: < checkrule (why not dude)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO < 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 200
=== ID TEST 3.3: < checkrule (why not dude)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:7" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO < 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412
=== ID TEST 3.4: > checkrule (why not dude)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:8" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO > 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 200

=== ID TEST 3.5: > checkrule (why not dude)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$FOO:9" id:1999;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO > 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412


=== ID TEST 4.0: super long exception (trigger 400 bad request on old versions)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
         CheckRule "$FOO > 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- request eval
use URI::Escape;
"POST /
a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2=<>(){}[]'--;=a&a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1=<>(){}[]'--;=a&a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3=<>(){}[]'--;=a&a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4=<>(){}[]'&a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5=<>(){}[]'"
--- error_code: 200

