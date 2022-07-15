#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== WL TEST X.0: URL case sensitive wl
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 BasicRule wl:1999,1000 "mz:$URL:/foobar/tableDropdown|URL";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar/tableDropdown
--- error_code: 404

=== WL TEST X.1: URL case sensitive wl
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 BasicRule wl:1000 "mz:$URL:/wp-content/plugins/ultimate-tinymce/tableDropdown/editor_plugin.js|URL";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /wp-content/plugins/ultimate-tinymce/tableDropdown/editor_plugin.js
--- error_code: 404
=== WL TEST 6.3: Whitelists trying to provoke collisions
--- user_files
>>> buixor
eh yo
>>> bla
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 BasicRule wl:1999 "mz:$ARGS_VAR:/bla";
	 BasicRule wl:1998 "mz:$URL:/bla|ARGS";
}	 
location /RequestDenied {
	 return 412;
}
--- request
GET /bla?/bla=1999&bu=1998
--- error_code: 200
