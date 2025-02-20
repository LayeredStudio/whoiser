import { strict as assert } from 'node:assert'
import { suite, test } from 'node:test'

import { whoisAsn, whoisIp, whoisTld } from './whoiser.ts'

suite('whoisAsn()', () => {
	test('reserved ASN', async () => {
		assert.rejects(whoisAsn(1))
		assert.rejects(whoisAsn(4294967295))
	})

	test('AS15169', async () => {
		const whois = await whoisAsn(15169)

		assert.equal(whois['ASHandle'], 'AS15169', 'AS Number doesn\'t match')
		assert.equal(whois['ASName'], 'GOOGLE', 'AS Name doesn\'t match')
	})

	test('AS13335', async () => {
		const whois = await whoisAsn(13335)

		assert.equal(whois['ASNumber'], '13335', 'AS Number doesn\'t match')
		assert.equal(whois['ASHandle'], 'AS13335', 'AS Number doesn\'t match')
		assert.equal(whois['ASName'], 'CLOUDFLARENET', 'AS Name doesn\'t match')
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
		assert.equal(whois['range'], '1.1.1.0 - 1.1.1.255', 'IP Range doesn\'t match')
		assert.equal(whois['route'], '1.1.1.0/24', 'IP Route doesn\'t match')
	})

	test('8.8.8.8', async () => {
		const whois = await whoisIp('8.8.8.8')

		assert.equal(whois['NetName'], 'GOGL')
		assert.equal(whois['organisation']['Country'], 'US')
		assert.equal(whois['range'], '8.8.8.0 - 8.8.8.255', 'IP Range doesn\'t match')
		assert.equal(whois['route'], '8.8.8.0/24', 'IP Route doesn\'t match')
	});

	test('2606:4700:4700::1111', async () => {
		const whois = await whoisIp('2606:4700:4700::1111')

		assert.equal(whois['asn'], 'AS13335')
		assert.equal(whois['NetName'], 'CLOUDFLARENET')
		assert.equal(whois['organisation']['Country'], 'US')
		assert.equal(whois['range'], '2606:4700:: - 2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 'IP Range doesn\'t match')
		assert.equal(whois['route'], '2606:4700::/32', 'IP Route doesn\'t match')
	});

	test('2001:4860:4860::8888', async () => {
		const whois = await whoisIp('2001:4860:4860::8888')

		assert.equal(whois['asn'], 'AS15169')
		assert.equal(whois['NetName'], 'GOOGLE-IPV6')
		assert.equal(whois['organisation']['Country'], 'US')
		assert.equal(whois['range'], '2001:4860:: - 2001:4860:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 'IP Range doesn\'t match')
		assert.equal(whois['route'], '2001:4860::/32', 'IP Route doesn\'t match')
	});
})

suite('whoisTld()', () => {
	test('invalid TLDs', () => {
		assert.rejects(whoisTld('-abc'))
		assert.rejects(whoisTld('thistldshouldntexist'))
	})

	test('com', async () => {
		const whois = await whoisTld('com')

		assert.equal(whois.tld, 'COM', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.verisign-grs.com', 'WHOIS server doesn\'t match')
		assert.equal(whois.created, '1985-01-01')
	})

	test('.google', async () => {
		const whois = await whoisTld('.google')

		assert.equal(whois.tld, 'GOOGLE', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.nic.google', 'WHOIS server doesn\'t match')
	})

	test('.香港 - IDN', async () => {
		const whois = await whoisTld('.香港')
		assert.equal(whois.tld, '香港', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.hkirc.hk', 'WHOIS server doesn\'t match')
	})

	test('com.au - SLD', async () => {
		const whois = await whoisTld('com.au')
		assert.equal(whois.tld, 'AU', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.auda.org.au', 'WHOIS server doesn\'t match')
		assert.equal(whois.created, '1986-03-05')
	})

	test('uk - TLD/SLD match', async () => {
		const whois1 = await whoisTld('uk')
		const whois2 = await whoisTld('co.uk')
		const whois3 = await whoisTld('google.co.uk')

		assert.equal(whois1.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
		assert.equal(whois2.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
		assert.equal(whois3.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
	})
})
