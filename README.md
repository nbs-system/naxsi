<img alt="naxsi logo" src="https://www.nbs-system.com/wp-content/uploads/nbs-logo-naxsi1.png" align="center"/>   

[![coverity](https://scan.coverity.com/projects/1883/badge.svg)](https://scan.coverity.com/projects/1883)
[![travis-ci](https://travis-ci.org/nbs-system/naxsi.svg?branch=master)](https://travis-ci.org/nbs-system/naxsi)
[![coveralls](https://coveralls.io/repos/github/nbs-system/naxsi/badge.svg?branch=master)](https://coveralls.io/github/nbs-system/naxsi?branch=master)
[![codecov](http://codecov.io/github/nbs-system/naxsi/coverage.svg?branch=master)](http://codecov.io/github/nbs-system/naxsi?branch=master)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/740/badge)](https://bestpractices.coreinfrastructure.org/projects/740)
[![Gitter](https://img.shields.io/gitter/room/nwjs/nw.js.svg)](https://gitter.im/nbs-system/naxsi)

### We need your help

[Please fill in this little feedback survey](https://docs.google.com/spreadsheet/viewform?formkey=dG9UWDFuTEhiWWt4UF9fZEtwWFVJUlE6MQ), 2 minutes of your time, great help for us !


## What is Naxsi?

NAXSI means [Nginx]( http://nginx.org/ ) Anti [XSS]( https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29 ) & [SQL Injection]( https://www.owasp.org/index.php/SQL_injection ). 

Technically, it is a third party nginx module, available as a package for
many UNIX-like platforms. This module, by default, reads a small subset of
[simple (and readable) rules]( https://github.com/nbs-system/naxsi/blob/master/naxsi_config/naxsi_core.rules )
containing 99% of known patterns involved in
website vulnerabilities. For example, `<`, `|` or `drop` are not supposed
to be part of a URI.

Being very simple, those patterns may match legitimate queries, it is
the Naxsi's administrator duty to add specific rules that will whitelist
legitimate behaviours. The administrator can either add whitelists manually
by analyzing nginx's error log, or (recommended) start the project with an
intensive auto-learning phase that will automatically generate whitelisting
rules regarding a website's behaviour.

In short, Naxsi behaves like a DROP-by-default firewall, the only task
is to add required ACCEPT rules for the target website to work properly.

## Why is it different?

Contrary to most Web Application Firewalls, Naxsi doesn't rely on a
signature base like an antivirus, and thus cannot be circumvented by an
"unknown" attack pattern. Another main difference between Naxsi and other
WAFs, Naxsi filters only GET and POST requests,
is [Free software]( https://www.gnu.org/licenses/gpl.html ) (as in freedom)
and free (as in free beer) to use.

## What does it run on?
Naxsi is compatible with any nginx version, although it currently doesn't play well with the new HTTPv2 protocol added in recent nginx versions. See [issue #227]( https://github.com/nbs-system/naxsi/issues/227 ) for more details.

It depends on `libpcre` for its regexp support, and is reported to work great on NetBSD, FreeBSD, OpenBSD, Debian, Ubuntu and CentOS.

### Getting started

- The [documentation](https://github.com/nbs-system/naxsi/wiki)
- Some [rules]( https://github.com/nbs-system/naxsi-rules ) for mainstream software
- The [nxapi/nxtool]( https://github.com/nbs-system/naxsi/tree/master/nxapi ) to generate rules


<img alt="nxapi-dashboard logo" src="https://raw.githubusercontent.com/wiki/nbs-system/naxsi/Images/kibana.png" align="center"/>   

## Security issues
If you find a security issue, please send it by email to `tko@nbs-system.com`;
you can use the gpg key
[0x251A28DE2685AED4](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x251A28DE2685AED4)
to encrypt it.
