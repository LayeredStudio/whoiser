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
		});

		it('should return IP WHOIS for "1.1.1.1"', async function() {
			let whois = await whoiser('1.1.1.1')
			assert.ok(whois.length)
		});

		/*
		it('should return ASN WHOIS for "1234"', async function() {
			let whois = await whoiser('1234')
			assert.ok(whois.length)
		});
		*/

		it('should reject for unrecognised query "-abc"', function() {
			assert.rejects(whoiser('-abc'))
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

		it('should return WHOIS for "google.li" when whois data is "label:_EOL_value"', async function() {
			let whois = await whoiser.domain('google.li', {follow: 1})
			assert.equal(whois['whois.nic.li']['Domain name'], 'google.li', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.nic.li']['Name servers'].length, 0, 'Does not return NS')
			assert.equal(whois['whois.nic.li']['First registration date'], '2000-08-04', 'Reg date doesn\'t match')
		});

		it('should return WHOIS for "google.eu" when whois data is "label:_EOL_value"', async function() {
			let whois = await whoiser.domain('google.eu', {follow: 1})
			assert.equal(whois['whois.eu']['Domain'], 'google.eu', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.eu']['Name servers'].length, 0, 'Does not return NS')
		});
	});

	describe('#whoiser.ip()', function() {
		it('should return WHOIS for "8.8.8.8"', async function() {
			let whois = await whoiser.ip('8.8.8.8')
			whois = whois.join("\n")
			assert.notStrictEqual(whois.indexOf('NetRange:       8.8.8.0 - 8.8.8.255'), -1, 'IP range doesn\'t match')
		});

		it('should return WHOIS for "2606:4700:4700::1111"', async function() {
			let whois = await whoiser.ip('2606:4700:4700::1111')
			whois = whois.join("\n")
			assert.notStrictEqual(whois.indexOf('NetRange:       2606:4700:: - 2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'), -1, 'IP range doesn\'t match')
			assert.notStrictEqual(whois.indexOf('NetName:        CLOUDFLARENET'), -1, 'NetName doesn\'t match')
		});
	});

});
