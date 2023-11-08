![naxsi](https://raw.githubusercontent.com/nbs-system/naxsi/master/logo.png)

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
"unknown" attack pattern.
Naxsi is [Free software]( https://www.gnu.org/licenses/gpl.html ) (as in freedom)
and free (as in free beer) to use.

## What does it run on?
Naxsi should be compatible with any nginx version.

It depends on `libpcre` for its regexp support, and is reported to work great on NetBSD, FreeBSD, OpenBSD, Debian, Ubuntu and CentOS.

### Getting started

- The [documentation](https://github.com/nbs-system/naxsi/wiki)
- Some [rules]( https://github.com/nbs-system/naxsi-rules ) for mainstream software
- The [nxapi/nxtool]( https://github.com/nbs-system/naxsi/tree/master/nxapi ) to generate rules


<img alt="nxapi-dashboard logo" src="https://raw.githubusercontent.com/wiki/nbs-system/naxsi/Images/kibana.png" align="center"/>   

## Security issues


If you find a security issue, please send us a mail to the security user, on nbs-system.com, using the gpg key 498C46FF087EDC36E7EAF9D445414A82A9B22D78:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFnKHhoBCADaOa0MKEqRy0h2ohIzczblzkMQCbU9oD1HwJ1VkYnn7TGW2iKi
NISxisExIXpy2Bn/pA27GiV0V/Do3NL6D9r0oOCrGR27muGM0N/dk9UMv7MWw8zv
K8cO+Sa28s0cAv7r2ogUJj5YOo8D4wHEpE8424TE89V9+Qg/SaFCxKoELFP0c7wu
mtsm0PnL65piZ1EB7lQo2gxg+8AV45MD1Y2rREMKUoZE23X+nXKsmEh9BFEPaU5M
7WQp0NasqeMNoGhwfw9ttVAeLhkEkaTjW1PkNRIb7vrtV9KVb5uKucflfbOnDlzu
tQ9U3tYto0mcSCRchAClfEmoSi/0mKyb5N6ZABEBAAG0NVNlY3VyaXR5IHRlYW0g
b2YgTkJTIFN5c3RlbSA8c2VjdXJpdHlAbmJzLXN5c3RlbS5jb20+iQE3BBMBCAAh
BQJZyh4aAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEEVBSoKpsi14jy0H
/1/XB9THhvmG0ow81sld2Zx8qhnNed8VvYDS6mEjpDWNVPxENwDbnakEjisq1Hrb
2UQPYCyQ5dekPNFVwQHIGXkX0eb1Ank+4esBJuEpQ2985tgNhJy5ZX+Imb5C8nZC
90uYSN1UUg559nUsFeElOXSEH6tIXK/TvjsvMYoi2Ukl6lb7PbIU2fjLY9Iqv3QY
32p8/Bl1fVKWbXOk0HDgJ6zA3Kr56QhZOLBkxjOa2XAnnIE76jZxUJ9qPCwWd1vW
GFxtx1Y+eZriqHiC9CPe6aBWcIHaTXSu1WBbXrFu8/eCWw243Rxm8l9wgA/a7VWq
WBfO45IhJUwh95naRpw8/4a5AQ0EWcoeGgEIAJtzSyyzfn2RX+BsyoRFANUpIgrV
/9eohYQVNqK3AFthmq7Kjmt4+hszF5+0wCFmWwYqGnqk1/dsWmqpkXsJldEn6oPJ
Bng+Dc67Yki2dR3TroAf95UmI08fhyM7TMXp8m46BPRRMzPNwalEeEm49Oclmfxb
JsWWCChWVLWGz2xgPEAv3fPHqus7Rwz/WIl53l/qy1Wf0ewmjRpVEfnEMKBExtBK
4kRxQ40LzUZ1SfpyGc3nMbswhevT7/klqrdJdCnlu67Y/IfRGxGZuNj1n1Dib3Hx
zTBHo3Y2R3BB93Ix8dkbLaxLqFbOYVdijCgJklqUWhx7btpQ2xnZyzyCMuUAEQEA
AYkBHwQYAQgACQUCWcoeGgIbDAAKCRBFQUqCqbIteFRvB/9u3Mae8n8ELrJKOn+P
PEbWjutObIuTplvY4QcbnNb9dsgsKryamp4CFJsA5XuitPpC31GDMXBZO5/LLOuH
HoMaXFJdic0NToL/3REhu+aZkNIU6S/iaPRNVhkSV4lwQsvncz+nBaiDUJjyfJm2
kEjVcRTM8yqzcNo/9Gn0ts+XCUqRj7+S1M4Bj3NySoO/w2n+7OLbIAj+wQZcj3Gf
5QhBYaY4YaFxrJE0IZxyXGHw8xhKR6AN+u4TO7LRCW+cWV/sHWir1MXieJoEG8+R
W/BhrB0Rz5uxOXMoGCCD2TUiHq7zpuHGnYFVmAnHQZaaQxXve4VrcmznxgpV8lpW
mZug
=+eIv
-----END PGP PUBLIC KEY BLOCK-----
```
