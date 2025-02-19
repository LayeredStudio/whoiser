import { strict as assert } from 'node:assert'
import { suite, test } from 'node:test'

import { whoisTld } from './whoiser.ts'

suite('whoisTld', () => {
	test('whoisTld() - invalid tlds', function() {
		assert.rejects(whoisTld('-abc'))
		assert.rejects(whoisTld('thistldshouldntexist'))
	});

	test(`whoisTld('com')`, async function() {
		const whois = await whoisTld('com')
		assert.equal(whois.tld, 'COM', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.verisign-grs.com', 'WHOIS server doesn\'t match')
	});

	test(`whoisTld('.google')`, async function() {
		const whois = await whoisTld('.google')
		assert.equal(whois.tld, 'GOOGLE', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.nic.google', 'WHOIS server doesn\'t match')
	});

	test(`whoisTld('.香港') - IDN`, async function() {
		const whois = await whoisTld('.香港')
		assert.equal(whois.tld, '香港', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.hkirc.hk', 'WHOIS server doesn\'t match')
	});

	test(`whoisTld('com.au') - SLD`, async function() {
		const whois = await whoisTld('com.au')
		assert.equal(whois.tld, 'AU', 'TLD doesn\'t match')
		assert.equal(whois.whois, 'whois.auda.org.au', 'WHOIS server doesn\'t match')
		assert.equal(whois.created, '1986-03-05')
	});

	test(`whoisTld('uk') - TLD/SLD match`, async function() {
		const whois1 = await whoisTld('uk')
		const whois2 = await whoisTld('co.uk')
		const whois3 = await whoisTld('google.co.uk')

		assert.equal(whois1.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
		assert.equal(whois2.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
		assert.equal(whois3.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
	});
})

