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


# blacklist on static var name (good)
# blacklist on static var name (fail)


# blacklist on rx var name (good)
# blacklist on rx var name (fail)

# blacklist on rx var name (bad zone)
# blacklist on static var name (bad zone)


# blacklist on multi static var name (one good, multi-bad)
# blacklist on multi static var name (multi-bad)


# blacklist on multi rx var name (one good, multi-bad)
# blacklist on multi rx var name (multi-bad)







__DATA__
=== TEST 1.0: blacklist on static var name (good)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:foo" "s:$XSS:8";
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR:foo" "s:$XSS:8";
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foo[0-9]+$" "s:$XSS:8";
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule id:4241 "str:ratata" "mz:$ARGS_VAR_X:^foo[0-9]+$" "s:$XSS:8";
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule id:4241 "str:ratata" "mz:$BODY_VAR_X:^foo[0-9]+$" "s:$XSS:8";
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
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


