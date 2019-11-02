# 🌍 Whoiser

**whoiser** is a WHOIS client for Node.js than helps with querying WHOIS servers for TLDs, domain names, AS numbers and IPs.

Has support for auto-discovery WHOIS servers for TLDs and IPs allocators, making it easy to get WHOIS info with a single call like `whoiser('google.com')` or `whoiser('1.1.1.1')`.
Applies minimal parsing to results, returning same data format from different WHOIS servers.

## Highlights
* Returns WHOIS info for any internet address
* Requires zero config, but configurable when needed
* Recognises queries and routes the request to correct server
* Minimal parsing to provide consistent results across WHOIS servers
* Uses WHOIS servers from IANA, if not provided
* Discover all available TLDs

## Roadmap
Aiming to have these features:
- [x] helper function to query WHOIS servers -> `whoiser.query()`
- [x] query whois for TLDs with parsed result -> `whoiser.tld()`
- [x] query whois for domains with parsed result -> `whoiser.domain()`
- [x] query whois for IPs and return parsed result -> `whoiser.ip()`
- [x] query whois for ASN with parsed result -> `whoiser.asn()`
- [x] Punycode support
- [ ] Normalize Domain WHOIS field names, removing inconsistencies between WHOIS servers
- [ ] Test more IPs and ASNs to deliver consistent WHOIS results

## Getting Started

#### Installation

```npm i whoiser```

#### Usage
The library has a simple API.
Use `whoiser(query)` with any query you would want OR use specific functions with options like `whoiser.domain(domain, {options})`, `whoiser.ip(ip, {options})`

### Domain whois

Get WHOIS info for domains

```js
const whoiser = require('whoiser');

(async () => {

	// WHOIS info with auto-discovering for WHOIS server
	let domainInfo = await whoiser('google.com')

	// OR with options for whois server and how many servers to check
	let domainInfo2 = await whoiser.domain('blog.google', {host: 'whois.nic.google', follow: 3})

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
        "Creation Date": "1997-09-15T00:00:00-0700",
        "Expiry Date": "2020-09-13T21:00:00-0700",
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
        "text": [
            "For more information on WHOIS status codes, please visit:",
            ...
        ]
    }
}
```

### IP whois

Get WHOIS info for IPs

```js
const whoiser = require('whoiser');

(async () => {

	// WHOIS info with auto-discovering for WHOIS server
	let ipInfo = await whoiser('1.1.1.1')

	// OR with options for whois server
	let ipInfo2 = await whoiser.ip('8.8.8.8', {host: 'whois.arin.net'})

	console.log(ipInfo, ipInfo2)
})();
```
Returns a promise which resolves with an `Array` of WHOIS info lines:
```js
{
  range: '2606:4700:: - 2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
  route: '2606:4700::/32',
  NetName: 'CLOUDFLARENET',
  NetHandle: 'NET6-2606-4700-1',
  Parent: 'NET6-2600 (NET6-2600-1)',
  NetType: 'Direct Allocation',
  asn: 'AS13335',
  Organization: 'Cloudflare, Inc. (CLOUD14)',
  RegDate: '2011-11-01',
  Updated: '2017-02-17',
  Comment: 'All Cloudflare abuse reporting can be done via  https://www.cloudflare.com/abuse',
  Ref: 'https://rdap.arin.net/registry/ip/2606:4700::',
}
```

### AS Number whois

Get WHOIS info for an AS number

```js
const whoiser = require('whoiser');

(async () => {

    // WHOIS info for ASN15169
    let whois = await whoiser.asn(15169)

    console.log(whois)
})();
```
Returns a promise which resolves with an `Object` of WHOIS info:
```js
{
  ASNumber: '15169',
  ASName: 'GOOGLE',
  ASHandle: 'AS15169',
  RegDate: '2000-03-30',
  Updated: '2012-02-24',
  Ref: 'https://rdap.arin.net/registry/autnum/15169',
}
```

## More

Please report any issues here on GitHub.
[Any contributions are welcome](CONTRIBUTING.md)

## License

[MIT](http://opensource.org/licenses/MIT)

Copyright (c) Andrei Igna, Layered
