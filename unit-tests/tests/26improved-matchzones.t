#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1.0: blacklist on static var name (good)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratz" "mz:$ARGS_VAR:foo1|$URL:/ff" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:foo" "s:$XSS:8";
MainRule id:4241 "str:ratz" "mz:$ARGS_VAR:foo1" "s:$XSS:8";
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
}
--- request
GET /?foo=ratataXXX
--- error_code: 412
=== TEST 1.1: blacklist on static var name (bad)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:foo1/$URL:/zz" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:foo" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:foo/$URL:/zz" "s:$XSS:8";
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
}
--- request
GET /?foox=ratataXXX
--- error_code: 200
=== TEST 2.0: blacklist on rx var name (good)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foa[0-9]+$|$URL_X:/f1" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foo[0-9]+$" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foa[0-9]+$|$URL_X:/ff" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foa[0-9]+$" "s:$XSS:8";
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
}
--- request
GET /?foo888=ratataXXX
--- error_code: 412
=== TEST 2.1: blacklist on rx var name (bad)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foo[0-9]+$/$URL_X:/z" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foo[0-9]+$" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^fo1[0-9]+$" "s:$XSS:8";
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
}
--- request
GET /?foob=ratataXXX
--- error_code: 200
=== TEST 3.0: blacklist on rx var name (bad zone)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$BODY_VAR_X:^foo[0-9]+$|$URL_X:/fz" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$BODY_VAR_X:^foo[0-9]+$" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$BODY_VAR_X:^fo1[0-9]+$" "s:$XSS:8";
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
}
--- request
GET /?foo88=ratataXXX
--- error_code: 200

=== TEST 3.1: blacklist on static var name (bad zone)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$BODY_VAR:foo|$URL:/f" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$BODY_VAR:foo" "s:$XSS:8";
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
}
--- request
GET /?foo=ratataXXX
--- error_code: 200

=== TEST 4.0: blacklist on multi static var name (one good, many bad)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL:/zz|$ARGS_VAR:aaa|$ARGS_VAR:foo|$ARGS_VAR:nope" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:aaa|$ARGS_VAR:foo|$ARGS_VAR:nope" "s:$XSS:8";
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
}
--- request
GET /?foo=ratataXXX
--- error_code: 412

=== TEST 4.1: blacklist on multi rx var name (one good, many bad)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL_X:^/z$|$ARGS_VAR_X:^aaa$|$ARGS_VAR_X:^foo$|$ARGS_VAR_X:^nope$" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^aaa$|$ARGS_VAR_X:^foo$|$ARGS_VAR_X:^nope$" "s:$XSS:8";
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
}
--- request
GET /?foo=ratataXXX
--- error_code: 412


=== TEST 5.0: blacklist on multi rx var name (many bad)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^aaa$|$ARGS_VAR_X:^foo$|$ARGS_VAR_X:^nope$" "s:$XSS:8";
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
}
--- request
GET /?foo1=ratataXXX
--- error_code: 200


=== TEST 5.1: blacklist on multi rx var name (many bad, one good zone)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^aaa$|$ARGS_VAR_X:^foo$|$ARGS_VAR_X:^nope$|ARGS" "s:$XSS:8";
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
}
--- request
GET /?foo1=ratataXXX
--- error_code: 412


=== TEST 6.0: blacklist on multi static var name (many bad)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:^aaa$|$ARGS_VAR:^foo$|$ARGS_VAR:^nope$" "s:$XSS:8";
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
}
--- request
GET /?foo1=ratataXXX
--- error_code: 200


=== TEST 6.1: blacklist on multi static var name (many bad, one good zone)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:^aaa$|$ARGS_VAR:^foo$|$ARGS_VAR:^nope$|ARGS" "s:$XSS:8";
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
}
--- request
GET /?foo1=ratataXXX
--- error_code: 412

=== TEST 7.0: static blacklist on $URL:/ | $ARGS_VAR  (both good)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL:/fooa|$ARGS_VAR:aaa" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$URL:/foo|$ARGS_VAR:aaa" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$URL:/fooz|$ARGS_VAR:aaa" "s:$XSS:8";
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
}
--- request
GET /foo?aaa=ratataXXX
--- error_code: 412


=== TEST 7.1: static blacklist on $URL:/ | $ARGS_VAR  (bad url)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL:/foo1|$ARGS_VAR:aaa" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$URL:/foo|$ARGS_VAR:aaa" "s:$XSS:8";
MainRule id:4241 "str:ratata" "mz:$URL:/foo2|$ARGS_VAR:aaa" "s:$XSS:8";
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
}
--- request
GET /foox?aaa=ratataXXX
--- error_code: 404



=== TEST 7.2: static blacklist on $URL:/ | $ARGS_VAR  (bad ARGS_VAR)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL:/foo|$ARGS_VAR:aaa" "s:$XSS:8";
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
}
--- request
GET /foo?axaa=ratataXXX
--- error_code: 404

=== TEST 7.3: static blacklist on $URL:/ | $ARGS_VAR  (one bad ARGS_VAR and one good)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL:/foo|$ARGS_VAR:aaa|$ARGS_VAR:tutu" "s:$XSS:8";
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
}
--- request
GET /foo?tutu=ratataXXX
--- error_code: 412


=== TEST 7.0: rx blacklist on $URL_X:/ | $ARGS_VAR_X  (both good)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL_X:^/foo$|$ARGS_VAR_X:^aaa[0-9]+$" "s:$XSS:8";
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
}
--- request
GET /foo?aaa4242=ratataXXX
--- error_code: 412


=== TEST 7.1: rx blacklist on $URL_X:/ | $ARGS_VAR_X  (bad url)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL_X:^/foo$|$ARGS_VAR_X:^aaa$" "s:$XSS:8";
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
}
--- request
GET /foox?aaa=ratataXXX
--- error_code: 404



=== TEST 7.2: rx blacklist on $URL_X:/ | $ARGS_VAR_X  (bad ARGS_VAR)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL_X:^/foo$|$ARGS_VAR_X:^aaa$" "s:$XSS:8";
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
}
--- request
GET /foo?axaa=ratataXXX
--- error_code: 404

=== TEST 7.3: static blacklist on $URL:/ | $ARGS_VAR  (one bad ARGS_VAR and one good)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4241 "str:ratata" "mz:$URL_X:^/foo$|$ARGS_VAR_X:^aaa$|$ARGS_VAR_X:^tutu$" "s:$XSS:8";
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
}
--- request
GET /foo?tutu=ratataXXX
--- error_code: 412


=== TEST 8.0: gni ?
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "mz:$ARGS_VAR_X:^foo.*" "msg:lol" "s:DROP" id:42424242;
#MainRule id:4241 "str:ratata" "mz:$URL_X:^/foo$|$ARGS_VAR_X:^aaa$|$ARGS_VAR_X:^tutu$" "s:$XSS:8";
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
}
--- request
GET /?fooxxxad=foobar
--- error_code: 412

