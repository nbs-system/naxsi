use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== ID TEST 1.0: Disabled IDs
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
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
         BasicRule wl:1999;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 200
=== ID TEST 1.1: Disabled IDs (fail)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
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
         BasicRule wl:1999;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1998
--- error_code: 412
=== ID TEST 1.2: Disabled negative IDs
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
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
         BasicRule wl:-1999;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1998
--- error_code: 200
=== ID TEST 1.3: Disabled negative IDs (fail)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
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
         BasicRule wl:-1999;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412
=== ID TEST 1.4: Multiple Disabled negative IDs
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
         BasicRule wl:-1999,-1998;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1997
--- error_code: 200
=== ID TEST 1.5: Multiple Disabled negative IDs
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
         BasicRule wl:-1999,-1998;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?bla=1999
--- error_code: 412


=== ID TEST 2.0: BasicRule negative id test
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
         BasicRule wl:-1999 "mz:$URL:/|$ARGS_VAR:foo";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo=1999
--- error_code: 412


=== ID TEST 2.1: BasicRule negative id test (fail)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
         BasicRule wl:-1999 "mz:$URL:/|$ARGS_VAR:foo";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo=1998
--- error_code: 200


=== ID TEST 2.2: BasicRule negative id test (fail on internal ID)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
	 BasicRule wl:-1999 "mz:$URL:/|$ARGS_VAR:foo";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo=a%00a
--- error_code: 412


=== ID TEST 3.0: Partial disabled whitelist
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS|URL" "s:$SQL:42" id:1999;
# MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
# MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
	 BasicRule wl:1999 "mz:ARGS";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo=a1999a
--- error_code: 200

=== ID TEST 3.1: Partial disabled whitelist (fail zone)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS|URL" "s:$SQL:42" id:1999;
# MainRule "str:1998" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1998;
# MainRule "str:1997" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1997;
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
	 BasicRule wl:1999 "mz:ARGS";
}
location /RequestDenied {
         return 412;
}
--- request
GET /1999?foo=aa
--- error_code: 412

=== ID TEST 4.0: header disabled rule
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:HEADERS|ARGS" "s:$SQL:42" id:1998;
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
--- more_headers
foo: 1998
--- request
GET /
--- error_code: 412

=== ID TEST 4.1: header disabled rule wl
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:1998" "msg:foobar test pattern #1" "mz:HEADERS|ARGS" "s:$SQL:42" id:1998;
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
	 BasicRule wl:1998 "mz:HEADERS";
}
location /RequestDenied {
         return 412;
}
--- more_headers
foo: 1998
--- request
GET /
--- error_code: 200

