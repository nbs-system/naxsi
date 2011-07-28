#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(3);

plan tests => repeat_each(1) * 2 * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1: Basic GET request
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=buibui
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"


=== TEST 2: DENY : Obvious GET XSS
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a="><ScRiPt>alert(1)</scRiPt>
--- response_body eval
"FORBIDDEN.#
"
=== TEST 2.1: DENY : Obvious RFI
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 2" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=http://evil.com/eva.txt
--- response_body eval
"FORBIDDEN.#
"
=== TEST 2.3: DENY : Obvious LFI
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 2" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=../../../../../bar.txt
--- response_body eval
"FORBIDDEN.#
"
=== TEST 3: OBVIOUS GET SQL INJECTION
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=1'+Or+'1'='1
--- response_body eval
"FORBIDDEN.#
"
=== TEST 3bis: OBVIOUS (quoteless) GET SQL INJECTION
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=1+UnIoN+SeLeCt+1
--- response_body eval
"FORBIDDEN.#
"

