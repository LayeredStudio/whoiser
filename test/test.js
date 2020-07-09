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
