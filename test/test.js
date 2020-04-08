const assert = require('assert')
const whoiser = require('../index.js')

describe('Whoiser', function() {

	describe('#whoiser()', function() {
		it('should return TLD WHOIS for "blog"', async function() {
			let whois = await whoiser('blog')
			assert.equal(whois.domain, 'BLOG', 'TLD doesn\'t match')
		});

		it('should return domain WHOIS for "google.com"', async function() {
			let whois = await whoiser('google.com')
			assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'GOOGLE.COM', 'Domain name doesn\'t match')
			assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '2138514_DOMAIN_COM-VRSN', 'Registry Domain ID doesn\'t match')

			for (const whoisServer in whois) {
				assert(Object.keys(whois[whoisServer]).includes('Expiry Date'), 'Whois result doesn\'t have "Expiry Date"')
			}
		});

		it('should return IP WHOIS for "1.1.1.1"', async function() {
			let whois = await whoiser('1.1.1.1')
			assert.equal(whois.range, '1.1.1.0 - 1.1.1.255', 'IP Range doesn\'t match')
			assert.equal(whois.route, '1.1.1.0/24', 'IP Route doesn\'t match')
		});

		it('should return AS WHOIS for "15169"', async function() {
			let whois = await whoiser('15169')
			assert.equal(whois.ASName, 'GOOGLE', 'AS Name doesn\'t match')
		});

		it('should reject for unrecognised query "-abc"', function() {
			assert.throws(() => whoiser('-abc'), Error)
		});
	});

	describe('#whoiser.tld()', function() {
		it('should return WHOIS for "com"', async function() {
			const whois = await whoiser.tld('com')
			assert.equal(whois.domain, 'COM', 'TLD doesn\'t match')
			assert.equal(whois.whois, 'whois.verisign-grs.com', 'WHOIS server doesn\'t match')
		});

		it('should return WHOIS for "google"', async function() {
			let whois = await whoiser.tld('blog.google')
			assert.equal(whois.domain, 'GOOGLE', 'TLD doesn\'t match')
			assert.equal(whois.whois, 'whois.nic.google', 'WHOIS server doesn\'t match')
		});

		it('should return WHOIS for ".香港" - IDN', async function() {
			let whois = await whoiser('.香港')
			assert.equal(whois.domain, '香港', 'TLD doesn\'t match')
			assert.equal(whois.whois, 'whois.hkirc.hk', 'WHOIS server doesn\'t match')
		});

		it('should return WHOIS for ".XN--J6W193G" - IDN', async function() {
			let whois = await whoiser('.XN--J6W193G')
			assert.equal(whois.domain, '香港', 'TLD doesn\'t match')
			assert.equal(whois.whois, 'whois.hkirc.hk', 'WHOIS server doesn\'t match')
		});

		it('should reject for invalid TLD format', function() {
			assert.rejects(whoiser.tld('-abc'))
		});

		it('should reject for non-existing TLD', function() {
			assert.rejects(whoiser.tld('thistldshouldntexist', {
				name:		'Error',
				message:	'TLD "thistldshouldntexist" not found'
			}))
		});
	});

	describe('#whoiser.domain()', function() {
		it('should return WHOIS for "blog.google"', async function() {
			let whois = await whoiser.domain('blog.google')
			assert.equal(whois['whois.nic.google']['Domain Name'], 'blog.google', 'Domain name doesn\'t match')
			assert.equal(whois['whois.nic.google']['Registry Domain ID'], '27CAA9F68-GOOGLE', 'Registry Domain ID doesn\'t match')
		});

		it('should return WHOIS for "cloudflare.com" from "whois.cloudflare.com" server (host option)', async function() {
			let whois = await whoiser.domain('cloudflare.com', {host: 'whois.cloudflare.com'})
			assert.equal(Object.values(whois).length, 1, 'Has less or more than 1 WHOIS result')
			assert.deepStrictEqual(Object.keys(whois), ['whois.cloudflare.com'], 'Has whois result from server different than "whois.cloudflare.com"')
			assert.equal(whois['whois.cloudflare.com']['Domain Name'], 'CLOUDFLARE.COM', 'Domain name doesn\'t match')
		});

		it('should return WHOIS for "laye.red" from top-level whois server (follow option)', async function() {
			let whois = await whoiser.domain('laye.red', {follow: 1})
			assert.equal(Object.values(whois).length, 1, 'Has less or more than 1 WHOIS result')
			assert.deepStrictEqual(Object.keys(whois), ['whois.afilias.net'], 'Has whois result from server different than "whois.afilias.net"')
			assert.equal(whois['whois.afilias.net']['Domain Name'], 'LAYE.RED', 'Domain name doesn\'t match')
		});

		/* fails because of timeout error..
		it('should return WHOIS for "google.li" when whois data is "label:_EOL_value"', async function() {
			let whois = await whoiser.domain('google.li', {follow: 1})
			assert.equal(whois['whois.nic.li']['Domain name'], 'google.li', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.nic.li']['Name servers'].length, 0, 'Does not return NS')
			assert.equal(whois['whois.nic.li']['First registration date'], '2000-08-04', 'Reg date doesn\'t match')
		});
		*/

		it('should return WHOIS for "notion.so" with correct registrar WHOIS server', async function() {
			let whois = await whoiser.domain('notion.so', {follow: 1})
			assert.equal(whois['whois.nic.so']['Registry WHOIS Server'], 'whois.nic.so', 'Parsing error for WHOIS server')
		});

		it('should return WHOIS for "goo.gl" with correct registrar WHOIS server', async function() {
			let whois = await whoiser.domain('goo.gl', {follow: 1})
			assert.equal(whois['whois.nic.gl']['Registry WHOIS Server'], 'whois.nic.gl', 'Parsing error for WHOIS server')
		});

		it('should return WHOIS for "google.eu" when whois data is "label:_EOL_value"', async function() {
			let whois = await whoiser.domain('google.eu', {follow: 1})
			assert.equal(whois['whois.eu']['Domain Name'], 'google.eu', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.eu']['Name Server'].length, 0, 'Does not return NS')
		});

		it('should return WHOIS for "mañana.com" - IDN', async function() {
			let whois = await whoiser.domain('mañana.com')
			assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'XN--MAANA-PTA.COM', 'Domain name doesn\'t match')
			assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '123697069_DOMAIN_COM-VRSN', 'Domain ID doesn\'t match')
		});

		it('should return WHOIS for "XN--MAANA-PTA.COM" - IDN', async function() {
			let whois = await whoiser.domain('XN--MAANA-PTA.COM')
			assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'XN--MAANA-PTA.COM', 'Domain name doesn\'t match')
			assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '123697069_DOMAIN_COM-VRSN', 'Domain ID doesn\'t match')
		});
	});

	describe('#whoiser.asn()', function() {
		it('should return WHOIS for "15169"', async function() {
			let whois = await whoiser.asn(15169)
			assert.equal(whois.ASNumber, '15169', 'AS Number doesn\'t match')
			assert.equal(whois.ASName, 'GOOGLE', 'AS Name doesn\'t match')
		});

		it('should return WHOIS for "AS13335"', async function() {
			let whois = await whoiser.asn('AS13335')
			assert.equal(whois.ASNumber, '13335', 'AS Number doesn\'t match')
			assert.equal(whois.ASName, 'CLOUDFLARENET', 'AS Name doesn\'t match')
		});
	});

	describe('#whoiser.ip()', function() {
		it('should return WHOIS for "8.8.8.8"', async function() {
			let whois = await whoiser.ip('8.8.8.8')
			assert.equal(whois.range, '8.0.0.0 - 8.127.255.255', 'IP Range doesn\'t match')
			assert.equal(whois.route, '8.0.0.0/9', 'IP Route doesn\'t match')
		});

		it('should return WHOIS for "2606:4700:4700::1111"', async function() {
			let whois = await whoiser.ip('2606:4700:4700::1111')
			assert.equal(whois.range, '2606:4700:: - 2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 'IP Range doesn\'t match')
			assert.equal(whois.route, '2606:4700::/32', 'IP Route doesn\'t match')
		});
	});

});
