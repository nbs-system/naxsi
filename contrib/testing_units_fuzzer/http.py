from sulley import *
import sys

########################################################################################################################
s_initialize("HTTP VERBS BASIC")
s_group("verbs", values=["GET", "HEAD"])
if s_block_start("body", group="verbs"):
    s_static(" ")
    s_delim(" ")
    s_static("/")
    s_string("index.html")
    s_delim("> ")
    s_string("HTTP")
    s_delim("/")
    s_string("1")
    s_delim(".")
    s_string("0")
    s_static("\r\n\r\n")
s_block_end()


########################################################################################################################
s_initialize("HTTP VERBS POST")
s_static("POST / HTTP/1.0\r\n")
s_static("Content-Type: ")
s_string("application/x-www-form-urlencoded")
s_static("\r\n")
s_static("Content-Length: ")
s_size("post blob", format="ascii", signed=True, fuzzable=True)
s_static("\r\n\r\n")

if s_block_start("post blob"):
    s_string("A"*100 + "=" + "B1"*100)
s_block_end()


########################################################################################################################
s_initialize("HTTP HEADERS")
s_static("GET / HTTP/1.1\r\n")

# let's fuzz random headers with malformed delimiters.
s_string("Host")
s_delim(":")
s_delim(" ")
s_string("localhost")
s_delim("\r\n")

# let's fuzz the value portion of some popular headers.
s_static("User-Agent: ")
s_string("Mozilla/5.0 (Windows; U)")
s_static("\r\n")

s_static("Accept-Language: ")
s_string("en-us")
s_delim(",")
s_string("en;q=0.5")
s_static("\r\n")

s_static("Keep-Alive: ")
s_string("300")
s_static("\r\n")

s_static("Connection: ")
s_string("keep-alive")
s_static("\r\n")

s_static("Referer: ")
s_string("http://dvlabs.tippingpoint.com")
s_static("\r\n")
s_static("\r\n")


########################################################################################################################
s_initialize("HTTP COOKIE")
s_static("GET / HTTP/1.0\r\n")

if s_block_start("cookie"):
    s_static("Cookie: ")
    s_string("auth")
    s_delim("=")
    s_string("1234567890<a>")
    s_static("\r\n")
    s_block_end()

s_repeat("cookie", max_reps=5000, step=500)
s_static("\r\n")


s_initialize("HTTP VERBS")
s_group("verbs", values=["GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND"])
if s_block_start("body", group="verbs"):
    s_delim(" ")
    s_delim("/")
    s_string("index.html")
    s_delim("<a ")
    s_string("HTTP")
    s_delim("/")
    s_string("1")
    s_delim(".")
    s_string("0")
    s_static("\r\n\r\n")
s_block_end()

sess = sessions.session()
gc=0
fw=None
for target in ("HTTP VERBS", "HTTP COOKIE", "HTTP VERBS BASIC", "HTTP VERBS POST",
               "HTTP HEADERS"):
    if (fw is not None):
        fw.close()
        fw = None
    fw = open(target+"-ut.t", "w+")
    fw.write("# fuzzed testcase. ")
    fw.write("""
use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
""")
    req = s_get(target)
    for i in xrange(0,150):
        gc = gc + 1
        s_mutate()

        fw.write("=== "+str(gc)+" in "+target+"\n")
        fw.write("""--- main_config
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
--- raw_request eval\n""")
        fw.write("\""+req.render()+"\"\n")
        if (target is "foobar"):
            fw.write("--- error_code: 400\n\n")
        # elif (target is "HTTP HEADERS"):
        #     fw.write("--- error_code: 400\n\n")
        # elif (target is "HTTP VERBS BASIC"):
        #     fw.write("--- error_code: 400\n\n")
        else:
            fw.write("--- error_code: 400\n\n")
#        print(req.render())
#        print("#END")
sys.exit(1);

########################################################################################################################
