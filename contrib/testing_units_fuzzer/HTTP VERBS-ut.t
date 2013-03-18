# fuzzed testcase. 
use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== 1 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /index.html<a HTTP/1.0

"
--- error_code: 400

=== 2 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"HEAD /index.html<a HTTP/1.0

"
--- error_code: 400

=== 3 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"POST /index.html<a HTTP/1.0

"
--- error_code: 400

=== 4 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"OPTIONS /index.html<a HTTP/1.0

"
--- error_code: 400

=== 5 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"TRACE /index.html<a HTTP/1.0

"
--- error_code: 400

=== 6 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"PUT /index.html<a HTTP/1.0

"
--- error_code: 400

=== 7 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"DELETE /index.html<a HTTP/1.0

"
--- error_code: 400

=== 8 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"PROPFIND /index.html<a HTTP/1.0

"
--- error_code: 400

=== 9 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET  /index.html<a HTTP/1.0

"
--- error_code: 400

=== 10 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET     /index.html<a HTTP/1.0

"
--- error_code: 400

=== 11 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET          /index.html<a HTTP/1.0

"
--- error_code: 400

=== 12 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET                         /index.html<a HTTP/1.0

"
--- error_code: 400

=== 13 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET                                                                                                    /index.html<a HTTP/1.0

"
--- error_code: 400

=== 14 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    /index.html<a HTTP/1.0

"
--- error_code: 400

=== 15 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        /index.html<a HTTP/1.0

"
--- error_code: 400

=== 16 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET/index.html<a HTTP/1.0

"
--- error_code: 400

=== 17 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET	/index.html<a HTTP/1.0

"
--- error_code: 400

=== 18 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET		/index.html<a HTTP/1.0

"
--- error_code: 400

=== 19 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET																																																																																																				/index.html<a HTTP/1.0

"
--- error_code: 400

=== 20 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /index.html<a HTTP/1.0

"
--- error_code: 400

=== 21 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET	/index.html<a HTTP/1.0

"
--- error_code: 400

=== 22 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 /index.html<a HTTP/1.0

"
--- error_code: 400

=== 23 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
/index.html<a HTTP/1.0

"
--- error_code: 400

=== 24 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET!/index.html<a HTTP/1.0

"
--- error_code: 400

=== 25 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET@/index.html<a HTTP/1.0

"
--- error_code: 400

=== 26 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET#/index.html<a HTTP/1.0

"
--- error_code: 400

=== 27 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET$/index.html<a HTTP/1.0

"
--- error_code: 400

=== 28 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET%/index.html<a HTTP/1.0

"
--- error_code: 400

=== 29 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET^/index.html<a HTTP/1.0

"
--- error_code: 400

=== 30 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET&/index.html<a HTTP/1.0

"
--- error_code: 400

=== 31 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET*/index.html<a HTTP/1.0

"
--- error_code: 400

=== 32 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET(/index.html<a HTTP/1.0

"
--- error_code: 400

=== 33 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET)/index.html<a HTTP/1.0

"
--- error_code: 400

=== 34 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET-/index.html<a HTTP/1.0

"
--- error_code: 400

=== 35 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET_/index.html<a HTTP/1.0

"
--- error_code: 400

=== 36 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET+/index.html<a HTTP/1.0

"
--- error_code: 400

=== 37 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET=/index.html<a HTTP/1.0

"
--- error_code: 400

=== 38 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET:/index.html<a HTTP/1.0

"
--- error_code: 400

=== 39 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : /index.html<a HTTP/1.0

"
--- error_code: 400

=== 40 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7/index.html<a HTTP/1.0

"
--- error_code: 400

=== 41 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET;/index.html<a HTTP/1.0

"
--- error_code: 400

=== 42 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET'/index.html<a HTTP/1.0

"
--- error_code: 400

=== 43 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET\"/index.html<a HTTP/1.0

"
--- error_code: 400

=== 44 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET//index.html<a HTTP/1.0

"
--- error_code: 400

=== 45 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET\/index.html<a HTTP/1.0

"
--- error_code: 400

=== 46 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET?/index.html<a HTTP/1.0

"
--- error_code: 400

=== 47 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET</index.html<a HTTP/1.0

"
--- error_code: 400

=== 48 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET>/index.html<a HTTP/1.0

"
--- error_code: 400

=== 49 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET./index.html<a HTTP/1.0

"
--- error_code: 400

=== 50 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET,/index.html<a HTTP/1.0

"
--- error_code: 400

=== 51 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET/index.html<a HTTP/1.0

"
--- error_code: 400

=== 52 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET
/index.html<a HTTP/1.0

"
--- error_code: 400

=== 53 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET































































/index.html<a HTTP/1.0

"
--- error_code: 400

=== 54 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET































































































































/index.html<a HTTP/1.0

"
--- error_code: 400

=== 55 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET































































































































































































































































































































































































































































































































/index.html<a HTTP/1.0

"
--- error_code: 400

=== 56 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //index.html<a HTTP/1.0

"
--- error_code: 400

=== 57 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /////index.html<a HTTP/1.0

"
--- error_code: 400

=== 58 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //////////index.html<a HTTP/1.0

"
--- error_code: 400

=== 59 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /////////////////////////index.html<a HTTP/1.0

"
--- error_code: 400

=== 60 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ////////////////////////////////////////////////////////////////////////////////////////////////////index.html<a HTTP/1.0

"
--- error_code: 400

=== 61 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////index.html<a HTTP/1.0

"
--- error_code: 400

=== 62 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////index.html<a HTTP/1.0

"
--- error_code: 400

=== 63 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET index.html<a HTTP/1.0

"
--- error_code: 400

=== 64 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET  index.html<a HTTP/1.0

"
--- error_code: 400

=== 65 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 	index.html<a HTTP/1.0

"
--- error_code: 400

=== 66 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 index.html<a HTTP/1.0

"
--- error_code: 400

=== 67 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
index.html<a HTTP/1.0

"
--- error_code: 400

=== 68 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET !index.html<a HTTP/1.0

"
--- error_code: 400

=== 69 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET @index.html<a HTTP/1.0

"
--- error_code: 400

=== 70 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET #index.html<a HTTP/1.0

"
--- error_code: 400

=== 71 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET $index.html<a HTTP/1.0

"
--- error_code: 400

=== 72 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET %index.html<a HTTP/1.0

"
--- error_code: 400

=== 73 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ^index.html<a HTTP/1.0

"
--- error_code: 400

=== 74 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET &index.html<a HTTP/1.0

"
--- error_code: 400

=== 75 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET *index.html<a HTTP/1.0

"
--- error_code: 400

=== 76 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET (index.html<a HTTP/1.0

"
--- error_code: 400

=== 77 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET )index.html<a HTTP/1.0

"
--- error_code: 400

=== 78 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET -index.html<a HTTP/1.0

"
--- error_code: 400

=== 79 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET _index.html<a HTTP/1.0

"
--- error_code: 400

=== 80 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET +index.html<a HTTP/1.0

"
--- error_code: 400

=== 81 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET =index.html<a HTTP/1.0

"
--- error_code: 400

=== 82 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET :index.html<a HTTP/1.0

"
--- error_code: 400

=== 83 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : index.html<a HTTP/1.0

"
--- error_code: 400

=== 84 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET :7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7:7index.html<a HTTP/1.0

"
--- error_code: 400

=== 85 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ;index.html<a HTTP/1.0

"
--- error_code: 400

=== 86 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 'index.html<a HTTP/1.0

"
--- error_code: 400

=== 87 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET \"index.html<a HTTP/1.0

"
--- error_code: 400

=== 88 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /index.html<a HTTP/1.0

"
--- error_code: 400

=== 89 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET \index.html<a HTTP/1.0

"
--- error_code: 400

=== 90 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ?index.html<a HTTP/1.0

"
--- error_code: 400

=== 91 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET <index.html<a HTTP/1.0

"
--- error_code: 400

=== 92 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET >index.html<a HTTP/1.0

"
--- error_code: 400

=== 93 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET .index.html<a HTTP/1.0

"
--- error_code: 400

=== 94 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET ,index.html<a HTTP/1.0

"
--- error_code: 400

=== 95 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET index.html<a HTTP/1.0

"
--- error_code: 400

=== 96 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 
index.html<a HTTP/1.0

"
--- error_code: 400

=== 97 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 































































index.html<a HTTP/1.0

"
--- error_code: 400

=== 98 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 































































































































index.html<a HTTP/1.0

"
--- error_code: 400

=== 99 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET 































































































































































































































































































































































































































































































































index.html<a HTTP/1.0

"
--- error_code: 400

=== 100 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /<a HTTP/1.0

"
--- error_code: 400

=== 101 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //.:/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  <a><a HTTP/1.0

"
--- error_code: 400

=== 102 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //.../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  <a><a HTTP/1.0

"
--- error_code: 400

=== 103 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //.../.../.../.../.../.../.../.../.../.../<a><a HTTP/1.0

"
--- error_code: 400

=== 104 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //../../../../../../../../../../../../etc/passwd<a><a HTTP/1.0

"
--- error_code: 400

=== 105 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //../../../../../../../../../../../../boot.ini<a><a HTTP/1.0

"
--- error_code: 400

=== 106 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /..:..:..:..:..:..:..:..:..:..:..:..:..:<a><a HTTP/1.0

"
--- error_code: 400

=== 107 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /\\*<a><a HTTP/1.0

"
--- error_code: 400

=== 108 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /\\?\<a><a HTTP/1.0

"
--- error_code: 400

=== 109 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\<a><a HTTP/1.0

"
--- error_code: 400

=== 110 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.<a><a HTTP/1.0

"
--- error_code: 400

=== 111 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /!@#$%%^#$%#$@#$%$$@#$%^^**(()<a><a HTTP/1.0

"
--- error_code: 400

=== 112 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%01%02%03%04%0a%0d%0aADSF<a><a HTTP/1.0

"
--- error_code: 400

=== 113 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%01%02%03@%04%0a%0d%0aADSF<a><a HTTP/1.0

"
--- error_code: 400

=== 114 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET //%00/<a><a HTTP/1.0

"
--- error_code: 400

=== 115 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%00/<a><a HTTP/1.0

"
--- error_code: 400

=== 116 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%00<a><a HTTP/1.0

"
--- error_code: 400

=== 117 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%u0000<a><a HTTP/1.0

"
--- error_code: 400

=== 118 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%ώπ% ÿ<a><a HTTP/1.0

"
--- error_code: 400

=== 119 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ%ώπ%ÿ<a><a HTTP/1.0

"
--- error_code: 400

=== 120 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n<a><a HTTP/1.0

"
--- error_code: 400

=== 121 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n<a><a HTTP/1.0

"
--- error_code: 400

=== 122 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"\"%n\"<a><a HTTP/1.0

"
--- error_code: 400

=== 123 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s<a><a HTTP/1.0

"
--- error_code: 400

=== 124 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s<a><a HTTP/1.0

"
--- error_code: 400

=== 125 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"\"%s\"<a><a HTTP/1.0

"
--- error_code: 400

=== 126 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /1;SELECT%20*<a HTTP/1.0

"
--- error_code: 400

=== 127 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /'sqlattempt1<a HTTP/1.0

"
--- error_code: 400

=== 128 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /(sqlattempt2)<a HTTP/1.0

"
--- error_code: 400

=== 129 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /OR%201=1<a HTTP/1.0

"
--- error_code: 400

=== 130 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /ή­Ύο<a HTTP/1.0

"
--- error_code: 400

=== 131 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /ή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύο<a HTTP/1.0

"
--- error_code: 400

=== 132 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /ή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύο<a HTTP/1.0

"
--- error_code: 400

=== 133 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /ή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύο<a HTTP/1.0

"
--- error_code: 400

=== 134 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /ή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύοή­Ύο<a HTTP/1.0

"
--- error_code: 400

=== 135 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        <a HTTP/1.0

"
--- error_code: 400

=== 136 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><a HTTP/1.0

"
--- error_code: 400

=== 137 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 138 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 139 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 140 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 141 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 142 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 143 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 144 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 145 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 146 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 147 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 148 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 149 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

=== 150 in HTTP VERBS
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- http_config
include /etc/nginx/naxsi_core.rules;
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
         return 400;
         }
--- raw_request eval
"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<a HTTP/1.0

"
--- error_code: 400

