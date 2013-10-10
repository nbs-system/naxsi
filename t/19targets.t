use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== ID TEST 1.0: Drop rule without learning
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- http_config
include /etc/nginx/naxsi_core.rules;
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




