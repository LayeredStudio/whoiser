const assert = require('assert')
const whoiser = require('../index.js')

describe('#whoiser.domain()', function() {

	describe('Basic domain WHOIS', function() {
		it('returns WHOIS for "blog.google"', async function() {
			const whois = await whoiser.domain('blog.google')
			const firstWhois = whoiser.firstResult(whois)

			assert.equal(firstWhois['Domain Name'], 'blog.google', 'Domain name doesn\'t match')
			assert.equal(firstWhois['Registry Domain ID'], '27CAA9F68-GOOGLE', 'Registry Domain ID doesn\'t match')
		});

		it('returns WHOIS for "google.co.uk"', async function() {
			const whois = await whoiser.domain('google.co.uk')
			const firstWhois = whoiser.firstResult(whois)

			assert.equal(firstWhois['Domain Name'], 'google.co.uk', 'Domain name doesn\'t match')
			assert.equal(firstWhois['Created Date'], '14-Feb-1999', 'Created Date doesn\'t match')
		});

		it('returns WHOIS for "cloudflare.com" from "whois.cloudflare.com" server (host option)', async function() {
			let whois = await whoiser.domain('cloudflare.com', {host: 'whois.cloudflare.com'})
			assert.equal(Object.values(whois).length, 1, 'Has less or more than 1 WHOIS result')
			assert.deepStrictEqual(Object.keys(whois), ['whois.cloudflare.com'], 'Has whois result from server different than "whois.cloudflare.com"')
			assert.equal(whois['whois.cloudflare.com']['Domain Name'], 'CLOUDFLARE.COM', 'Domain name doesn\'t match')
		});

		it('returns WHOIS for "laye.red" from top-level whois server (follow option)', async function() {
			let whois = await whoiser.domain('laye.red', {follow: 1})
			assert.equal(Object.values(whois).length, 1, 'Has less or more than 1 WHOIS result')
			assert.deepStrictEqual(Object.keys(whois), ['whois.nic.red'], 'Has whois result from server different than "whois.nic.red"')
			assert.equal(whois['whois.nic.red']['Domain Name'], 'laye.red', 'Domain name doesn\'t match')
		});
	});

	describe('Domain WHOIS parsing (handles multi-line whois, different labels and more)', function() {

		/* fails because of timeout error..
		it('return WHOIS for "google.li" when whois data is "label:_EOL_value"', async function() {
			let whois = await whoiser.domain('google.li', {follow: 1})
			assert.equal(whois['whois.nic.li']['Domain name'], 'google.li', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.nic.li']['Name servers'].length, 0, 'Does not return NS')
			assert.equal(whois['whois.nic.li']['First registration date'], '2000-08-04', 'Reg date doesn\'t match')
		});
		*/

		it('should return WHOIS for "de" when domain includes an umlaut', async function () {
			// https://github.com/LayeredStudio/whoiser/issues/93
			const whoisUnicode = await whoiser.domain('testä.de', { follow: 1 })
			const whoisAscii = await whoiser.domain('xn--test-ooa.de', { follow: 1 })
			assert.notEqual(whoisUnicode['whois.denic.de']['Domain Status'], 'invalid', 'Domain Status is reported as invalid (Unicode)')
			assert.notEqual(whoisAscii['whois.denic.de']['Domain Status'], 'invalid', 'Domain Status is reported as invalid (ASCII)')
		});

		it('returns WHOIS for "netflix.io" with correct registrar WHOIS server', async function() {
			let whois = await whoiser.domain('netflix.io', {follow: 1})
			assert.equal(whois['whois.nic.io']['Registrar WHOIS Server'], 'whois.markmonitor.com', 'Parsing error for WHOIS server')
		});

		it('returns WHOIS for "goo.gl" with correct registrar WHOIS server', async function() {
			let whois = await whoiser.domain('goo.gl', {follow: 1})
			assert.equal(whois['whois.nic.gl']['Registrar WHOIS Server'], 'whois.markmonitor.com', 'Parsing error for WHOIS server')
		});

		it('returns WHOIS for "google.eu" when whois data is "label:_EOL_value"', async function() {
			let whois = await whoiser.domain('google.eu', {follow: 1})
			assert.equal(whois['whois.eu']['Domain Name'], 'google.eu', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.eu']['Name Server'].length, 0, 'Does not return NS')
		});

		it('returns WHOIS for "mañana.com" - IDN', async function() {
			let whois = await whoiser.domain('mañana.com')
			assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'XN--MAANA-PTA.COM', 'Domain name doesn\'t match')
			assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '123697069_DOMAIN_COM-VRSN', 'Domain ID doesn\'t match')
		});

		it('returns WHOIS for "XN--MAANA-PTA.COM" - IDN', async function() {
			let whois = await whoiser.domain('XN--MAANA-PTA.COM')
			assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'XN--MAANA-PTA.COM', 'Domain name doesn\'t match')
			assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '123697069_DOMAIN_COM-VRSN', 'Domain ID doesn\'t match')
		});

		it('returns WHOIS for "google.nl"', async function() {
			let whois = await whoiser.domain('google.nl')
			assert.equal(whois['whois.domain-registry.nl']['Domain Name'], 'google.nl', 'Domain name doesn\'t match')
			assert.equal(whois['whois.domain-registry.nl']['Name Server'].length, 4, 'Incorrect number of NS returned')
		});

		it('returns WHOIS for "jprs.jp"', async function() {
			let whois = await whoiser.domain('jprs.jp')
			assert.equal(whois['whois.jprs.jp']['Domain Name'], 'JPRS.JP', 'Domain name doesn\'t match')
			assert.equal(whois['whois.jprs.jp']['Name Server'].length, 4, 'Incorrect number of NS returned')
		});

		it('returns WHOIS for "ownit.nyc"', async function() {
			let whois = await whoiser.domain('ownit.nyc')
			assert.equal(whois['whois.nic.nyc']['Domain Name'], 'ownit.nyc', 'Domain name doesn\'t match')
			assert.equal(whois['whois.nic.nyc']['Name Server'].length, 6, 'Incorrect number of NS returned')
		});

		it('returns WHOIS for "nic.ua" with fieldsfor all type of contacts', async function() {
			let whois = await whoiser.domain('nic.ua')
			assert.equal(whois['whois.ua']['Domain Name'], 'nic.ua', 'Domain name doesn\'t match')
			assert.notStrictEqual(whois['whois.ua']['registrar organization-loc'], false, 'Does not return registrar name')
			assert.notStrictEqual(whois['whois.ua']['registrant organization-loc'], false, 'Does not return registrant name')
			assert.notStrictEqual(whois['whois.ua']['administrative contacts organization-loc'], false, 'Does not return admin name')
			assert.notStrictEqual(whois['whois.ua']['technical contacts organization-loc'], false, 'Does not return tech name')
		});

		it('returns WHOIS for "google.it"', async function () {
			let whois = await whoiser.domain('google.it')
			assert.equal(whois['whois.nic.it']['Domain Name'], 'google.it', 'Domain name doesn\'t match')
			assert.equal(whois['whois.nic.it']['Name Server'].length, 4, 'Incorrect number of NS returned')
			assert.equal(whois['whois.nic.it']['Registrar'], 'MarkMonitor International Limited MARKMONITOR-REG', 'Registrar name doesn\'t match')
			assert.equal(whois['whois.nic.it']['Created Date'], '1999-12-10 00:00:00', 'Creation date doesn\'t match')
			for (const property of ['Registrant', 'Admin Contact', 'Technical Contacts']) {
				const label = `${property} Created`
				assert.equal(typeof whois['whois.nic.it'][label], 'string', `${label} does not exist, or is not a string`)
			}
		})
	});

});
