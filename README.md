# 🌍 Whoiser

**whoiser** is a JS library than helps with querying WHOIS servers for TLDs, domain names and IPs.

Has support for auto-discovering WHOIS servers for TLDs and IPs allocators, making it easy to get WHOIS info with a single call like `whoiser('google.com')` or `whoiser('1.1.1.1')`.

## Use cases
* Get WHOIS info for any domian
* Get ASN or route for IPs
* Discover available TLDs
* Get status or importand dates for domains

## Getting Started

#### Installation

```npm i whoiser```

#### Usage
The library has a simple API.

**Domain whois** - Get WHOIS info for domains:
```js
const whoiser = require('whoiser');

(async () => {

    // WHOIS info with auto-discovering for WHOIS server
	let domainInfo = await whoiser('google.com')

	// OR with options for whois server and how many servers to check
	let domainInfo2 = await whoiser.domain('blog.google', {whoisServer: 'whois.nic.google', follow: 3})

    console.log(domainInfo, domainInfo2)
})();
```
Returns a promise which resolves with an `Object` of WHOIS servers checked:
```js
{
    "whois.verisign-grs.com": {
        "Domain Name": "GOOGLE.COM",
        "Registrar WHOIS Server": "whois.markmonitor.com",
        ...
    },
    "whois.markmonitor.com": {
        "Domain Name": "google.com",
        "Registrar WHOIS Server": "whois.markmonitor.com",
        "Registrar URL": "http://www.markmonitor.com",
        "Creation Date": "1997-09-15T00:00:00-0700",
        "Registrar Registration Expiration Date": "2020-09-13T21:00:00-0700",
        "Registrar": "MarkMonitor, Inc.",
        "Domain Status": [
            "clientUpdateProhibited",
            "clientTransferProhibited",
            "clientDeleteProhibited"
        ],
        ...
        "Name Server": [
            "ns1.google.com",
            "ns2.google.com",
            "ns3.google.com",
            "ns4.google.com"
        ],
        "DNSSEC": "unsigned",
        "text": [
            "For more information on WHOIS status codes, please visit:",
            ...
        ]
    }
}
```

**IP whois** - get WHOIS info for IPs:
```js
const whoiser = require('whoiser');

(async () => {

    // WHOIS info with auto-discovering for WHOIS server
	let ipInfo = await whoiser('1.1.1.1')

	// OR with options for whois server
	let ipInfo2 = await whoiser.ip('8.8.8.8', {whoisServer: 'whois.arin.net'})

    console.log(ipInfo, ipInfo2)
})();
```
Returns a promise which resolves with an `Array` of WHOIS info lines:
```js
[
    "% [whois.apnic.net]",
    "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html",
    "",
    "% Information related to '1.1.1.0 - 1.1.1.255'",
    "",
    "inetnum:        1.1.1.0 - 1.1.1.255",
    "netname:        APNIC-LABS",
    "country:        AU",
    "last-modified:  2018-03-30T01:51:28Z",
    "source:         APNIC",
    ...
    "route:          1.1.1.0/24",
    "origin:         AS13335",
    "descr:          APNIC Research and Development",
    "                6 Cordelia St",
]
```

## More

Please report any issues here on GitHub.
[Any contributions are welcome](CONTRIBUTING.md)

## License

[MIT](http://opensource.org/licenses/MIT)

Copyright (c) Andrei Igna, Layered
