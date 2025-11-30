import { strict as assert } from 'node:assert'
import { suite, test } from 'node:test'

import { whoisAsn, whoisDomain, whoisIp, whoisTld } from './whoiser.ts'

suite('whoisAsn()', () => {
	test('reserved ASN', { skip: true }, async () => {
		assert.rejects(() => whoisAsn(1))
		assert.rejects(() => whoisAsn(4294967295))
	})

	test('AS15169', async () => {
		const whois = await whoisAsn(15169)

		assert.equal(whois['ASHandle'], 'AS15169', "AS Number doesn't match")
		assert.equal(whois['ASName'], 'GOOGLE', "AS Name doesn't match")
	})

	test('AS13335', async () => {
		const whois = await whoisAsn(13335)

		assert.equal(whois['ASNumber'], '13335', "AS Number doesn't match")
		assert.equal(whois['ASHandle'], 'AS13335', "AS Number doesn't match")
		assert.equal(whois['ASName'], 'CLOUDFLARENET', "AS Name doesn't match")
	})
})

suite('Basic domain WHOIS', () => {
	/* test('returns WHOIS for "blog.google"', async function() {
		const whois = await whoisDomain('blog.google')
		const firstWhois = whoiser.firstResult(whois)

		assert.equal(firstWhois['Domain Name'], 'blog.google', 'Domain name doesn\'t match')
		assert.equal(firstWhois['Registry Domain ID'], '27CAA9F68-GOOGLE', 'Registry Domain ID doesn\'t match')
	}); */

	test('should return domain WHOIS for "google.com"', async function () {
		let whois = await whoisDomain('google.com')
		assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'GOOGLE.COM', "Domain name doesn't match")
		assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '2138514_DOMAIN_COM-VRSN', "Registry Domain ID doesn't match")

		for (const whoisServer in whois) {
			assert(Object.keys(whois[whoisServer]).includes('Expiry Date'), 'Whois result doesn\'t have "Expiry Date"')
		}
	})

	/* test('returns WHOIS for "google.co.uk"', async function() {
		const whois = await whoisDomain('google.co.uk')
		const firstWhois = whoiser.firstResult(whois)

		assert.equal(firstWhois['Domain Name'], 'google.co.uk', 'Domain name doesn\'t match')
		assert.equal(firstWhois['Created Date'], '14-Feb-1999', 'Created Date doesn\'t match')
	}); */

	test('returns WHOIS for "cloudflare.com" from "whois.cloudflare.com" server (host option)', async function () {
		let whois = await whoisDomain('cloudflare.com', { host: 'whois.cloudflare.com' })
		assert.equal(Object.values(whois).length, 1, 'Has less or more than 1 WHOIS result')
		assert.deepStrictEqual(Object.keys(whois), ['whois.cloudflare.com'], 'Has whois result from server different than "whois.cloudflare.com"')
		assert.equal(whois['whois.cloudflare.com']['Domain Name'], 'CLOUDFLARE.COM', "Domain name doesn't match")
	})

	test('returns WHOIS for "javascript.tm" from top-level whois server', async function () {
		let whois = await whoisDomain('javascript.tm')

		assert.equal(Object.values(whois).length, 1, 'Has less or more than 1 WHOIS result')
		assert.deepStrictEqual(Object.keys(whois), ['whois.nic.tm'], 'Expected whois result from server "whois.nic.tm"')
		assert.equal(whois['whois.nic.tm']['Domain Name'], 'javascript.tm', "Domain name doesn't match")
		assert.equal(whois['whois.nic.tm']['Registrant Organization'], 'Deno Land Inc.', 'Expected registrant organization to be Deno')
	})
})

suite('Domain WHOIS parsing (handles multi-line whois, different labels and more)', function () {
	/* fails because of timeout error..
	it('return WHOIS for "google.li" when whois data is "label:_EOL_value"', async function() {
		let whois = await whoiser.domain('google.li', {follow: 1})
		assert.equal(whois['whois.nic.li']['Domain name'], 'google.li', 'Domain name doesn\'t match')
		assert.notStrictEqual(whois['whois.nic.li']['Name servers'].length, 0, 'Does not return NS')
		assert.equal(whois['whois.nic.li']['First registration date'], '2000-08-04', 'Reg date doesn\'t match')
	});
	*/

	test('should return WHOIS for "de" when domain includes an umlaut', async function () {
		// https://github.com/LayeredStudio/whoiser/issues/93
		const whoisUnicode = await whoisDomain('testä.de', { follow: 1 })
		const whoisAscii = await whoisDomain('xn--test-ooa.de', { follow: 1 })
		assert.notEqual(whoisUnicode['whois.denic.de']['Domain Status'], 'invalid', 'Domain Status is reported as invalid (Unicode)')
		assert.notEqual(whoisAscii['whois.denic.de']['Domain Status'], 'invalid', 'Domain Status is reported as invalid (ASCII)')
	})

	test('returns WHOIS for "netflix.io" with correct registrar WHOIS server', async function () {
		let whois = await whoisDomain('netflix.io', { follow: 1 })
		assert.equal(whois['whois.nic.io']['Registrar WHOIS Server'], 'whois.markmonitor.com', 'Parsing error for WHOIS server')
	})

	test('returns WHOIS for "goo.gl" with correct registrar WHOIS server', async function () {
		let whois = await whoisDomain('goo.gl', { follow: 1 })
		assert.equal(whois['whois.nic.gl']['Registrar WHOIS Server'], 'whois.markmonitor.com', 'Parsing error for WHOIS server')
	})

	test('returns WHOIS for "google.eu" when whois data is "label:_EOL_value"', async function () {
		let whois = await whoisDomain('google.eu', { follow: 1 })
		assert.equal(whois['whois.eu']['Domain Name'], 'google.eu', "Domain name doesn't match")
		assert.notStrictEqual(whois['whois.eu']['Name Server']?.length, 0, 'Does not return NS')
	})

	test('returns WHOIS for "mañana.com" - IDN', async function () {
		let whois = await whoisDomain('mañana.com')
		assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'XN--MAANA-PTA.COM', "Domain name doesn't match")
		assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '123697069_DOMAIN_COM-VRSN', "Domain ID doesn't match")
	})

	test('returns WHOIS for "XN--MAANA-PTA.COM" - IDN', async function () {
		let whois = await whoisDomain('XN--MAANA-PTA.COM')
		assert.equal(whois['whois.verisign-grs.com']['Domain Name'], 'XN--MAANA-PTA.COM', "Domain name doesn't match")
		assert.equal(whois['whois.verisign-grs.com']['Registry Domain ID'], '123697069_DOMAIN_COM-VRSN', "Domain ID doesn't match")
	})

	test('returns WHOIS for "google.nl"', async function () {
		let whois = await whoisDomain('google.nl')
		assert.equal(whois['whois.domain-registry.nl']['Domain Name'], 'google.nl', "Domain name doesn't match")
		assert.equal(whois['whois.domain-registry.nl']['Name Server']?.length, 4, 'Incorrect number of NS returned')
	})

	test('returns WHOIS for "jprs.jp"', async function () {
		let whois = await whoisDomain('jprs.jp')
		assert.equal(whois['whois.jprs.jp']['Domain Name'], 'JPRS.JP', "Domain name doesn't match")
		assert.equal(whois['whois.jprs.jp']['Name Server']?.length, 4, 'Incorrect number of NS returned')
	})

	test('returns WHOIS for "ownit.nyc"', async function () {
		let whois = await whoisDomain('ownit.nyc')
		assert.equal(whois['whois.nic.nyc']['Domain Name'], 'ownit.nyc', "Domain name doesn't match")
		assert.equal(whois['whois.nic.nyc']['Name Server']?.length, 6, 'Incorrect number of NS returned')
	})

	test('returns WHOIS for "google.bz"', async function () {
		let whois = await whoisDomain('google.bz')
		assert.equal(whois['whois.identity.digital']['Domain Name'], 'google.bz', "Domain name doesn't match")
		assert.equal(whois['whois.identity.digital']['Name Server']?.length, 4, 'Incorrect number of NS returned')
	})

	test('returns WHOIS for "nic.gi"', async function () {
		let whois = await whoisDomain('nic.gi')
		assert.equal(whois['whois.identity.digital']['Domain Name'], 'nic.gi', "Domain name doesn't match")
		assert.equal(whois['whois.identity.digital']['Registrar IANA ID'], '800072', "Registrar IANA ID doesn't match")
	})

	test('returns WHOIS for "google.lc"', async function () {
		let whois = await whoisDomain('google.lc')
		assert.equal(whois['whois.identity.digital']['Domain Name'], 'google.lc', "Domain name doesn't match")
		assert.equal(whois['whois.identity.digital']['Name Server']?.length, 4, 'Incorrect number of NS returned')
	})

	test('returns WHOIS for "google.vc"', async function () {
		let whois = await whoisDomain('google.vc')
		assert.equal(whois['whois.identity.digital']['Domain Name'], 'google.vc', "Domain name doesn't match")
		assert.equal(whois['whois.identity.digital']['Name Server']?.length, 4, 'Incorrect number of NS returned')
	})

	test('returns WHOIS for "nic.ua" with fieldsfor all type of contacts', async function () {
		let whois = await whoisDomain('nic.ua')
		assert.equal(whois['whois.ua']['Domain Name'], 'nic.ua', "Domain name doesn't match")
		assert.notStrictEqual(whois['whois.ua']['registrar organization-loc'], false, 'Does not return registrar name')
		assert.notStrictEqual(whois['whois.ua']['registrant organization-loc'], false, 'Does not return registrant name')
		assert.notStrictEqual(whois['whois.ua']['administrative contacts organization-loc'], false, 'Does not return admin name')
		assert.notStrictEqual(whois['whois.ua']['technical contacts organization-loc'], false, 'Does not return tech name')
	})

	test('returns WHOIS for "google.it"', async function () {
		let whois = await whoisDomain('google.it')
		assert.equal(whois['whois.nic.it']['Domain Name'], 'google.it', "Domain name doesn't match")
		assert.equal(whois['whois.nic.it']['Name Server']?.length, 4, 'Incorrect number of NS returned')
		assert.equal(whois['whois.nic.it']['Registrar'], 'MarkMonitor International Limited MARKMONITOR-REG', "Registrar name doesn't match")
		assert.equal(whois['whois.nic.it']['Created Date'], '1999-12-10 00:00:00', "Creation date doesn't match")
		for (const property of ['Registrant', 'Admin Contact', 'Technical Contacts']) {
			const label = `${property} Created`
			assert.equal(typeof whois['whois.nic.it'][label], 'string', `${label} does not exist, or is not a string`)
		}
	})

	test('returns WHOIS for "trabis.gov.tr"', async function () {
		let whois = await whoisDomain('trabis.gov.tr')
		assert.equal(whois['whois.trabis.gov.tr']['Domain Name'], 'trabis.gov.tr', "Domain name doesn't match")
		assert.equal(whois['whois.trabis.gov.tr']['Name Server']?.length, 2, 'Incorrect number of NS returned')
		assert.equal(whois['whois.trabis.gov.tr']['Registrar'], 'TRABİS KK', "Registrar name doesn't match")
		assert.equal(whois['whois.trabis.gov.tr']['Registrant Name'], 'Bilgi Teknolojileri ve İletişim Kurumu', "Registrant name doesn't match")
		assert.equal(whois['whois.trabis.gov.tr']['Created Date'], '2011-Mar-22', "Creation date doesn't match")
	})

	test('whois for google.fr', async () => {
		const whois = await whoisDomain('google.fr')
		const whoisServers = Object.keys(whois)

		assert.equal(whoisServers.length, 1, 'Returns 1 WHOIS server')

		const whoisData = whois[whoisServers[0]]

		assert.equal(whoisData['Domain Name'], 'google.fr', 'domain name ok')
		assert.equal(whoisData['Name Server']?.length, 4, '4 name servers')
		assert.equal(whoisData['Domain Status']?.length, 4, '4 statuses')
		assert.ok(
			whoisData['Domain Status'].find((s) => s === 'serverUpdateProhibited'),
			'4 name servers'
		)

		// dates
		assert.equal(whoisData['Expiry Date'], '2026-12-30T17:16:48Z')
		assert.equal(whoisData['Created Date'], '2000-07-26T22:00:00Z')

		// registrar
		assert.equal(whoisData['Registrar'], 'MARKMONITOR Inc.')
		assert.equal(whoisData['Registrar URL'], 'http://www.markmonitor.com')

		// registrant
		assert.equal(whoisData['Registrant Name'], 'Google Ireland Holdings Unlimited Company')
		assert.equal(whoisData['Registrant Email'], 'dns-admin@google.com')

		assert.ok(whois, 'No WHOIS data returned')
	})
})

suite('whoisIp()', () => {
	test('invalid IPs', () => {
		assert.rejects(whoisIp(''))
		assert.rejects(whoisIp('.'))
		assert.rejects(whoisIp(':'))
		assert.rejects(whoisIp('1'))
		assert.rejects(whoisIp('1.1.1.1.1'))
	})

	test('1.1.1.1', async () => {
		const whois = await whoisIp('1.1.1.1')

		assert.equal(whois['asn'], 'AS13335')
		assert.equal(whois['country'], 'AU')
		assert.equal(whois['range'], '1.1.1.0 - 1.1.1.255', "IP Range doesn't match")
		assert.equal(whois['route'], '1.1.1.0/24', "IP Route doesn't match")
	})

	test('8.8.8.8', async () => {
		const whois = await whoisIp('8.8.8.8')

		assert.equal(whois['NetName'], 'GOGL')
		assert.ok(whois['organisation'])
		assert.equal(whois['organisation']['Country'], 'US')
		assert.equal(whois['range'], '8.8.8.0 - 8.8.8.255', "IP Range doesn't match")
		assert.equal(whois['route'], '8.8.8.0/24', "IP Route doesn't match")
	})

	test('2606:4700:4700::1111', async () => {
		const whois = await whoisIp('2606:4700:4700::1111')
		//assert.equal(whois['asn'], 'AS13335')
		assert.equal(whois['NetName'], 'CLOUDFLARENET')
		assert.ok(whois['organisation'])
		assert.equal(whois['organisation']['Country'], 'US')
		assert.equal(whois['range'], '2606:4700:: - 2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', "IP Range doesn't match")
		assert.equal(whois['route'], '2606:4700::/32', "IP Route doesn't match")
	})

	test('2001:4860:4860::8888', async () => {
		const whois = await whoisIp('2001:4860:4860::8888')

		//assert.equal(whois['asn'], 'AS15169')
		assert.equal(whois['NetName'], 'GOOGLE-IPV6')
		assert.ok(whois['organisation'])
		assert.equal(whois['organisation']['Country'], 'US')
		assert.equal(whois['range'], '2001:4860:: - 2001:4860:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', "IP Range doesn't match")
		assert.equal(whois['route'], '2001:4860::/32', "IP Route doesn't match")
	})
})

suite('whoisTld()', () => {
	test('invalid TLDs', () => {
		assert.rejects(whoisTld('-abc'))
		assert.rejects(whoisTld('thistldshouldntexist'))
	})

	test('com', async () => {
		const whois = await whoisTld('com')

		assert.equal(whois.tld, 'COM', "TLD doesn't match")
		assert.equal(whois.whois, 'whois.verisign-grs.com', "WHOIS server doesn't match")
		assert.equal(whois.created, '1985-01-01')
	})

	test('.google', async () => {
		const whois = await whoisTld('.google')

		assert.equal(whois.tld, 'GOOGLE', "TLD doesn't match")
		assert.equal(whois.created, '2014-09-04', 'Expected creation date to be 2014-09-04')
	})

	test('.香港 - IDN', async () => {
		const whois = await whoisTld('.香港')
		assert.equal(whois.tld, '香港', "TLD doesn't match")
		assert.equal(whois.whois, 'whois.hkirc.hk', "WHOIS server doesn't match")
	})

	test('com.au - SLD', async () => {
		const whois = await whoisTld('com.au')
		assert.equal(whois.tld, 'AU', "TLD doesn't match")
		assert.equal(whois.whois, 'whois.auda.org.au', "WHOIS server doesn't match")
		assert.equal(whois.created, '1986-03-05')
	})

	test('uk - TLD/SLD match', async () => {
		const whois1 = await whoisTld('uk')
		const whois2 = await whoisTld('co.uk')
		const whois3 = await whoisTld('google.co.uk')

		assert.equal(whois1.whois, 'whois.nic.uk', "WHOIS server doesn't match")
		assert.equal(whois2.whois, 'whois.nic.uk', "WHOIS server doesn't match")
		assert.equal(whois3.whois, 'whois.nic.uk', "WHOIS server doesn't match")
	})
})
