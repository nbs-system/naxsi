# This File is used for broken tests.


use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
# This one should actually return 200, but a hashtable collision happens
=== WL TEST 6.1: Whitelist provoking collision
--- user_files
>>> buixor
eh yo
>>> bla
eh yo
--- http_config
include /etc/nginx/naxsi_core.rules;
MainRule "str:1998" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1998;
MainRule "str:1999" "msg:foobar test pattern #2" "mz:ARGS" "s:$SQL:42" id:1999;
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
         BasicRule wl:1999 "mz:$URL:/bla|ARGS|NAME";
         BasicRule wl:1998 "mz:$URL:/bla|ARGS";
}        
location /RequestDenied {
         return 412;
}
--- request
GET /bla?blx=1998&1999=bla
--- error_code: 412

