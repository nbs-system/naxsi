![naxsi](https://raw.githubusercontent.com/nbs-system/naxsi/master/logo.png)

## What is Naxsi?

NAXSI means [Nginx]( http://nginx.org/ ) Anti [XSS]( https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29 ) & [SQL Injection]( https://www.owasp.org/index.php/SQL_injection ). 

Technically, it is a third party nginx module, available as a package for
many UNIX-like platforms. This module, by default, reads a small subset of
simple (and readable) rules containing 99% of known patterns involved in
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
"unknown" attack pattern.
Naxsi is [Free software]( https://www.gnu.org/licenses/gpl.html ) (as in freedom)
and free (as in free beer) to use.

## What does it run on?
Naxsi should be compatible with any nginx version.

It depends on `libpcre` for its regexp support, and is reported to work great on NetBSD, FreeBSD, OpenBSD, Debian, Ubuntu and CentOS.

## Why using this repository

*The original project is (unofficially) abandoned*, but you can fully ask for support here as i'm willing to keep the project working as last remaining developer.

## Build naxsi

**Be sure when you clone the repository to fetch all the submodules.**

```
$ git clone --recurse-submodules https://github.com/wargio/naxsi.git
$ wget --no-clobber -O nginx.tar.gz "https://nginx.org/download/nginx-1.22.0.tar.gz"
$ mkdir nginx-source
$ tar -C nginx-source -xzf nginx.tar.gz --strip-components=1
$ cd nginx-source
$ ./configure  --prefix=/etc/nginx --add-dynamic-module=../naxsi/naxsi_src
$ make
```

## Support

You can ask for support regarding NAXSI here or on the original repository https://github.com/nbs-system/naxsi

## Future plans

- Bring back nxapi via py3
- Creation of a simple tool to create rules and test them
