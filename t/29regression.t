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
=== WL TEST 1.0: [ARGS zone WhiteList] Adding a test rule in http_config (ARGS zone) and disable rule.
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?driveOnDate=2016-11-29
--- error_code: 200

=== WL TEST 1.1: testing multiple alternate matching/non-matching rules
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:zz" "mz:$URL_X:/foo/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-json/wp/v2/?id=a
--- error_code: 412

=== WL TEST 1.2: testing multiple alternate matching/non-matching rules
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:zz" "mz:$URL_X:/foo/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-json/wp/v2?id=a
--- error_code: 404

=== WL TEST 1.3: testing multiple alternate matching/non-matching rules
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:zz" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-json/wp/v2?id=11
--- error_code: 404

=== WL TEST 1.4: testing multiple alternate matching/non-matching rules
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:zz" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-json/wp/v2/?id=zz
--- error_code: 412

=== WL TEST 1.5: testing multiple alternate matching/non-matching rules
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:zz" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
MainRule "str:iyxnlnjrf" "mz:$URL_X:^(/index.php)?/qquoteadv|ARGS|BODY" "s:DROP" "msg:base64_" id:42000526;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /qquoteadv?id=iyxnlnjrf1
--- error_code: 412
=== WL TEST 2.0: log + drop
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule negative "rx:^[\d_-]+$" "mz:$ARGS_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000530;
MainRule negative "rx:^[\d_-]+$" "mz:$BODY_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000529;
MainRule negative "rx:^\d+$" "mz:$ARGS_VAR_X:^id$|$URL_X:/wp-json/wp/v2/" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000531;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$BODY_VAR_X:^id$" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000532;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" DROP;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /wp-json/wp/v2/posts/111
id=1a&foo2=bar2"
--- error_code: 412
=== WL TEST 2.01: log + block
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;

--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule negative "rx:^[\d_-]+$" "mz:$ARGS_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000530;
MainRule negative "rx:^[\d_-]+$" "mz:$BODY_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000529;
MainRule negative "rx:^\d+$" "mz:$ARGS_VAR_X:^id$|$URL_X:/wp-json/wp/v2/" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000531;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$BODY_VAR_X:^id$" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000532;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /wp-json/wp/v2/posts/111
id=1a&foo2=bar2"
--- error_code: 412
=== WL TEST 3.0: false-positive on virtual-patch with empty var name
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:FOOBAR" "mz:$URL:/wp-includes/js/plupload/plupload.flash.swf|ARGS" "msg:Wordpress PlUpload XSS" "s:$UWA:8,$XSS_UWA:1"  id:42000485;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?a=bui&FOOBAR
--- error_code: 200
=== WL TEST 3.0: false-positive on virtual-patch with empty var name
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:FOOBAR" "mz:$URL:/wp-includes/js/plupload/plupload.flash.swf|ARGS" "msg:Wordpress PlUpload XSS" "s:$UWA:8,$XSS_UWA:1"  id:42000485;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-includes/js/plupload/plupload.flash.swf?a=bui&FOOBAR
--- error_code: 412
=== WL TEST 3.01: false-positive on virtual-patch with empty var name
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "rx:FOOBAR" "mz:$URL:/wp-includes/js/plupload/plupload.flash.swf|ARGS" "msg:Wordpress PlUpload XSS" "s:$UWA:8,$XSS_UWA:1"  id:42000485;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-includes/js/plupload/plupload.flash.swf/xxx/?a=bui&FOOBAR
--- error_code: 404

