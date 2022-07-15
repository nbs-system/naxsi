#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== RXWL TEST 1.0: simple wide regex ($args_var)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?bla=1999
--- error_code: 200
=== RXWL TEST 1.1: simple wide regex ($args_var)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?bra=1999
--- error_code: 412
=== RXWL TEST 1.2: simple wide regex ($args_var)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?aablaaa=1999
--- error_code: 200
=== RXWL TEST 1.3: simple end-restrictive regex ($args_var_x:..$)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla$";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?aabla=1999
--- error_code: 200
=== RXWL TEST 1.3: simple end-restrictive regex ($args_var_x:..$)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla$";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?aabla=1999
--- error_code: 200
=== RXWL TEST 1.4: simple end-restrictive regex ($args_var_x:..$)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla$";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?aablaa=1999
--- error_code: 412
=== RXWL TEST 1.5: simple begin-restrictive regex ($args_var_x:^..)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^bla";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?blaa=1999
--- error_code: 200
=== RXWL TEST 1.6: simple begin-restrictive regex ($args_var_x:^..)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^bla";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?blaa=1999
--- error_code: 200
=== RXWL TEST 1.7: simple begin-restrictive regex ($args_var_x:^..)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^bla";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?ablaa=1999
--- error_code: 412
=== RXWL TEST 1.8: simple full-restrictive regex ($args_var_x:^..$)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^bla$";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?abla=1999
--- error_code: 412
=== RXWL TEST 1.9: simple full-restrictive regex ($args_var_x:^..$)
--- user_files
>>> buixor
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^bla$";
}
location /RequestDenied {
         return 412;
}
--- request
GET /buixor?bla=1999
--- error_code: 200

=== RXWL TEST 2.0: simple wide regex ($args_var|$url)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla|$URL_X:/foo";
}
location /RequestDenied {
         return 412;
}
--- request
GET /foo?bla=1999
--- error_code: 200

=== RXWL TEST 2.1: simple wide regex ($args_var|$url)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:bla|$URL_X:/foo";
}
location /RequestDenied {
         return 412;
}
--- request
GET /foz?bla=1999
--- error_code: 412
=== RXWL TEST 2.2: simple half-restrictive regex ($args_var|$url)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^bla$|$URL_X:/foo";
}
location /RequestDenied {
         return 412;
}
--- request
GET /foo?blaz=1999
--- error_code: 412
=== RXWL TEST 3.0: simple wide regex (url|args|name)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$URL_X:/foo|ARGS|NAME";
}
location /RequestDenied {
         return 412;
}
--- request
GET /foo?19991999=foo
--- error_code: 200

=== RXWL TEST 3.1: simple wide regex (url|args|name)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$URL_X:/foo|ARGS|NAME";
}
location /RequestDenied {
         return 412;
}
--- request
GET /foo?foo=1999
--- error_code: 412

=== RXWL TEST 4.0: simple restrictive+complex regex ($URL_X|URL)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS|URL" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$URL_X:^/foo_[0-9]+_$|URL";
}
location /RequestDenied {
         return 412;
}
--- request
GET /foo_1999_?x=x
--- error_code: 404
=== RXWL TEST 4.1: simple restrictive+complex regex ($ARGS_VAR_X|NAME)
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS|URL" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^foo_[0-9]+_$|NAME";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo_1999_inject=x
--- error_code: 412
=== RXWL TEST 5.0: file ext ($URL|NAME) XXX
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:1999" "msg:foobar test pattern #1" "mz:ARGS|URL" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^foo_[0-9]+_$|NAME";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo_1999_inject=x
--- error_code: 412

=== RXWL TEST 6.0: case sensitiveness
--- user_files
>>> foo
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:abcd" "msg:foobar test pattern #1" "mz:ARGS|URL" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$ARGS_VAR_X:^foo_[0-9]+_$";
}
location /RequestDenied {
         return 412;
}
--- request
GET /?foo_1999_=ABCD
--- error_code: 200
