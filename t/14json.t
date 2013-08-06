#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== JSON0 : Valid JSON
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 200
=== JSON1 : invalid JSON (double closing ']')
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412



=== JSON2 : invalid JSON (missing closing ']')
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412
=== JSON3 : invalid JSON (closing array with '}' instead of ']')
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"}
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412
=== JSON4 : invalid JSON (Missing final closing '}')
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

"
--- error_code: 412

=== JSON5 : invalid JSON (Extra closing '}')
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}}"
--- error_code: 412
=== JSON6 : invalid JSON (Missing ',' in array)
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\" \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 412
=== JSON7 : Valid JSON with empty array item (Extra ',' in array)
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\",\"XML\",]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 200
=== JSON8 : valid JSON - too deep !
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{{{{{{{{{{{{[\"lol\"]}}}}}}}}}}}}"
--- error_code: 412
=== JSON9 : Valid JSON with ev0l stuff (array => var content)
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"G<ML\",\"XML\",]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 412
=== JSON10 : Valid JSON with ev0l stuff (array => var name)
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAl<so\": [\"GML\",\"XML\",]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 412
=== JSON11 : Empty JSON object
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{

}"
--- error_code: 200
=== JSON12 : malformed (closing object before array) Json 
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : [\"laul\", {\"die\" : \"nope\" ]}
}"
--- error_code: 412
=== JSON12 : malformed (unescaped quotes) 
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : [\"laul\", {\"die\" : \"n\"ope\" }]
}"
--- error_code: 412

=== JSON12 : escaped quotes 
--- http_config
include /etc/nginx/naxsi_core.rules;
--- config
set $naxsi_extensive_log 1;
location / {
	 BasicRule wl:1001,1205;
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : [\"laul\", {\"die\" : \"n\\\"ope\" }]
}"
--- error_code: 200
=== JSON13 : concatenation attempt (ie "foo":"bar"+eval(evil)+"foo")
--- http_config
include /etc/nginx/naxsi_core.rules;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : \"oh \"+eval(evil)+\" my\"]
}"
--- error_code: 412
=== JSON13 : concatenation attempt (ie "foo":"bar"+eval(evil)+"foo")
--- http_config
include /etc/nginx/naxsi_core.rules;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"obvious\" : \"a<a\"]
}"
--- error_code: 412
