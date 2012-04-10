#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== WL TEST 1.0: Obvious test in arg
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
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
GET /?foobar=a
--- error_code: 412

=== WL TEST 1.01: Check non-collision of zone and 'name' flag
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule id:5 "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42";
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
GET /?a=foobar
--- error_code: 412

=== WL TEST 1.1: Generic whitelist in ARGS_NAME
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 200


=== WL TEST 1.11: Generic whitelist in ARGS_NAME, limit
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 412

=== WL TEST 1.12: Generic whitelist in ARGS_NAME, limit
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 412

=== WL TEST 1.2: whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 200

=== WL TEST 1.21: whitelist in ARGS_NAME+$URL, limit
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 200

=== WL TEST 1.22: whitelist in ARGS_NAME+$URL, limit
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 412


=== WL TEST 1.3: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/z|ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 412

=== WL TEST 1.31: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|ARGS|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 412

=== WL TEST 1.32: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:b|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?b=foobar
--- error_code: 412

=== WL TEST 1.33: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=bui
--- error_code: 200

=== WL TEST 1.34: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:foobra" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:2999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
	 BasicRule wl:2999 "mz:$URL:/|$ARGS_VAR:foobar";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=foobra
--- error_code: 200

=== WL TEST 1.35: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:foobra" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:2999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
	 BasicRule wl:2999 "mz:$URL:/|$ARGS_VAR:foobar";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=foobar
--- error_code: 412

=== WL TEST 1.36: failed whitelist in ARGS_NAME+$URL
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:foobra" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:2999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
	 BasicRule wl:2999 "mz:$URL:/|$ARGS_VAR:foobar";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=foobar
--- error_code: 412


=== WL TEST 1.4: whitelist in ARGS_NAME+$URL+$ARGS_VAR
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 200

=== WL TEST 1.41: whitelist in ARGS_NAME+$URL+$ARGS_VAR
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 412



=== WL TEST 1.5: whitelist in ARGS_NAME+$URL+$ARGS_VAR, limit
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=foobar
--- error_code: 412


=== WL TEST 1.51: whitelist in ARGS_NAME+$URL+$ARGS_VAR, limit
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=foo
--- error_code: 200

=== WL TEST 1.6: whitelist in ARGS_NAME+$URL+$ARGS_VAR, (collision)
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar|NAME";
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:foobar";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=foobar
--- error_code: 200

