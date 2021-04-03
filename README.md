# 🌍 Whoiser

**whoiser** is a WHOIS client for Node.js than helps with querying WHOIS servers for TLDs, domain names, AS numbers and IPs.

Has support for auto-discovery WHOIS servers for TLDs and IPs allocators, making it easy to get WHOIS info with a single call like `whoiser('google.com')` or `whoiser('1.1.1.1')`.
Applies minimal parsing to results, returning same data format from different WHOIS servers.

### Highlights
* Returns WHOIS info for any internet address
* Requires zero config, but configurable when needed
* Recognises queries and routes the request to correct server
* Minimal parsing to provide consistent results across WHOIS servers
* Uses WHOIS servers from IANA, if not provided
* Discover all available TLDs

→ See it in action here https://dmns.app

## Getting Started

#### Installation

```npm i whoiser```

#### Usage
The library has a simple API.
Use `whoiser(query)` with any query you would want OR use specific functions with options like `whoiser.domain(domain, {options})`, `whoiser.ip(ip, {options})`

#### Example
```js
const whoiser = require('whoiser')

const domainWhois = whoiser('google.com')
const tldWhois = whoiser('.net')
const ipWhois = whoiser('1.1.1.1')
```

→ [See all examples](https://github.com/LayeredStudio/whoiser/tree/master/examples)

## Client API
- `whoiser(query, options)` - Get WHOIS data for any internet address
- [`whoiser.domain(domain, options)`](#domain-whois) - Get parsed WHOIS data for a domain
- `whoiser.tld(tld, options)` - Get WHOIS data for a TLD
- [`whoiser.asn(asn, options)`](#as-number-whois) - Get WHOIS data for an AS number
- [`whoiser.ip(ip, options)`](#ip-whois) - Get WHOIS data for a IP
- `whoiser.allTlds` - Returns a list of all TLDs, [downloaded from IANA](https://www.iana.org/domains/root/db)
- `whoiser.query(options)` - Query a WHOIS server for data

### Domain whois
Get WHOIS info for domains.

`whoiser.domain(domain, options): Promise<Object<whoisServer>>`
- `domain` - Domain name, excluding any subdomain. Ex: 'google.com'
- `options` - Object of options to use, all optional:
	- `host` - WHOIS server to query. Default: WHOIS server from IANA
	- `timeout` - WHOIS server request timeout in ms. Default: 1500
	- `follow` - How many WHOIS server to query. 1 = registry server (faster), 2 = registry + registrar (more domain details). Default: 2
	- `raw` - Return the raw WHOIS result in response. Added to `__raw`

```js
const whoiser = require('whoiser');

(async () => {

	// WHOIS info from Registry (Verisign) AND Registrar (MarkMonitor) whois servers
	let domainInfo = await whoiser('google.com')

	// OR with options for whois server and how many WHOIS servers to query
	let domainInfo2 = await whoiser.domain('blog.google', {host: 'whois.nic.google', follow: 1})

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
				"Creation Date": "1997-09-15T00:00:00-0700",
				"Expiry Date": "2020-09-13T21:00:00-0700",
				"Registrar": "MarkMonitor, Inc.",
				"Domain Status": [
						"clientUpdateProhibited",
						"clientTransferProhibited"
				],
				...
				"Name Server": [
						"ns1.google.com",
						"ns2.google.com"
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

`whoiser.ip(ip, options): Promise<Object>`
- `ip` - IP. Ex: '1.1.1.1'
- `options` - Object of options to use, all optional:
	- `host` - WHOIS server to query. Default: WHOIS server from IANA
	- `timeout` - WHOIS server request timeout in ms. Default: 1500
	- `raw` - Return the raw WHOIS result in response. Added to `__raw`

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
}
```

### AS Number whois

Get WHOIS info for an AS number

`whoiser.asn(asn, options): Promise<Object>`
- `asn` - ASN. Ex: 'AS15169' or `15169`
- `options` - Object of options to use, all optional:
	- `host` - WHOIS server to query. Default: WHOIS server from IANA
	- `timeout` - WHOIS server request timeout in ms. Default: 1500
	- `raw` - Return the raw WHOIS result in response. Added to `__raw`

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

## Unsupported TLDs
- `.ch` - WHOIS server for .ch doesn't return WHOIS info, works only in browser https://www.nic.ch/whois/. This library can be used only to check .ch domain availability, example here https://runkit.com/andreiigna/5efdeaa8e4f2d8001a00312d

## More

Please report any issues here on GitHub.
[Any contributions are welcome](CONTRIBUTING.md)

## License

[MIT](LICENSE)

Copyright (c) Andrei Igna, Layered
