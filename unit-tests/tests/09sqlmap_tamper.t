#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST: AND+%EF%BC%871%EF%BC%87=%EF%BC%871%EF%BC%87 UTF-8
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=AND+%EF%BC%871%EF%BC%87=%EF%BC%871%EF%BC%87 HTTP/1.0

"
--- error_code: 200


=== TEST: AND+%00%271%00%27=%00%271%00%27
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=AND+%00%271%00%27=%00%271%00%27 HTTP/1.0

"
--- error_code: 412


=== TEST: AND+1=1%00 Union select 1
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=AND+1=1%00%20Union%20select%201 HTTP/1.0

"
--- error_code: 412


=== TEST: base64, worthing checking
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=MScgQU5EIFNMRUVQKDUpIw== HTTP/1.0

"
--- error_code: 200


=== TEST: 'A+NOT+BETWEEN+0+AND+B'
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a='A+NOT+BETWEEN+0+AND+B' HTTP/1.0

"
--- error_code: 412


=== TEST: %2553%2545%254c%2545%2543%2554%2520%2546%2549%2545%254c%2544%2520%2546%2552%254f%254d%2520%2554%2541%2542%254c%2545
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=%2553%2545%254c%2545%2543%2554%2520%2546%2549%2545%254c%2544%2520%2546%2552%254f%254d%2520%2554%2541%2542%254c%2545 HTTP/1.0

"
--- error_code: 412


=== TEST: %53%45%4c%45%43%54%20%46%49%45%4c%44%20%46%52%4f%4d%20%54%41%42%4c%45
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=%53%45%4c%45%43%54%20%46%49%45%4c%44%20%46%52%4f%4d%20%54%41%42%4c%45 HTTP/1.0

"
--- error_code: 412


=== TEST: %u0053%u0045%u004c%u0045%u0043%u0054%u0020
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=%u0053%u0045%u004c%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004c%u0044%u0020%u0046%u0052%u004f%u004d%u0020%u0054%u0041%u0042%u004c%u0045' HTTP/1.0

"
--- error_code: 412


=== TEST: SELECT+*+FROM+users+WHERE+id+LIKE+1
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=SELECT+*+FROM+users+WHERE+id+LIKE+1 HTTP/1.0

"
--- error_code: 412


=== TEST: value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR'
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)),+NULL,+NULL#/*!0AND+'QDWa'='QDWa HTTP/1.0

"
--- error_code: 412


=== TEST: IF(ISNULL(1),+2,+1)
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=IF(ISNULL(1),+2,+1) HTTP/1.0

"
--- error_code: 412


=== TEST: 1+/*!30000AND+2>1*/--
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1+/*!30000AND+2>1*/-- HTTP/1.0

"
--- error_code: 412


=== TEST: 1+/*!00000AND+2>1*/--
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1+/*!00000AND+2>1*/-- HTTP/1.0

"
--- error_code: 412


=== TEST: +UNION+++SELECT++
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=+UNION+++SELECT++ HTTP/1.0

"
--- error_code: 412


=== TEST: IIS/ASP Encoding
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=%S%E%L%E%C%T+%F%I%E%L%D+%F%R%O%M+%T%A%B%L%E HTTP/1.0

"
--- error_code: 412


=== TEST: 1 UnioN SeLEct 1
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1%20UnioN%20SeLEct%201 HTTP/1.0

"
--- error_code: 412


=== TEST: AND+1=1+and+'0having'='0having'
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=AND+1=1+and+'0having'='0having' HTTP/1.0

"
--- error_code: 412


=== TEST: SELECT/**/id/**/FROM/**/users
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=SELECT/**/id/**/FROM/**/users HTTP/1.0

"
--- error_code: 412


=== TEST: 1--PTTmJopxdWJ%0AAND--cWfcVRPV%0A9227=9227
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1--PTTmJopxdWJ%0AAND--cWfcVRPV%0A9227=9227 HTTP/1.0

"
--- error_code: 412


=== TEST: 1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227 HTTP/1.0

"
--- error_code: 412


=== TEST: 1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227 HTTP/1.0

"
--- error_code: 412


=== TEST: SELECT%08id%02FROM%0Fusers
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=SELECT%08id%02FROM%0Fusers HTTP/1.0

"
--- error_code: 412


=== TEST: 1%23%0A9227=922%237
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1%23%0A9227=922%237 HTTP/1.0

"
--- error_code: 412


=== TEST: SELECT%0Bid%0BFROM%A0users
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=SELECT%0Bid%0BFROM%A0users HTTP/1.0

"
--- error_code: 412


=== TEST: 1--%0AAND--%0A9227=9227
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1--%0AAND--%0A9227=9227 HTTP/1.0

"
--- error_code: 412


=== TEST: SELECT+id+FROM+users
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=SELECT+id+FROM+users HTTP/1.0

"
--- error_code: 412



=== TEST: hey 28
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1%bf%27+AND+1=1--%20 HTTP/1.0

"
--- error_code: 412


=== TEST: hey 29
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,+CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER()/*!AS*//*!CHAR*/),CHAR(32)),CHAR(58,100,114,117,58))# HTTP/1.0

"
--- error_code: 412


=== TEST: hey 30
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
--- raw_request eval
"GET /?a=1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,/*!CONCAT*/(/*!CHAR*/(58,122,114,115,58),/*!IFNULL*/(CAST(/*!CURRENT_USER*/()/*!AS*//*!CHAR*/),/*!CHAR*/(32)),/*!CHAR*/(58,115,114,121,58))# HTTP/1.0

"
--- error_code: 412


