import { strict as assert } from 'node:assert'
import test from 'node:test'

import { whoisTld } from '../src/whoiser.ts'

test('whoisTld() - invalid tlds', function() {
	assert.rejects(whoisTld())
	assert.rejects(whoisTld('-abc'))
	assert.rejects(whoisTld('thistldshouldntexist'))
});

test(`whoisTld('com')`, async function() {
	const whois = await whoisTld('com')
	assert.equal(whois.domain, 'COM', 'TLD doesn\'t match')
	assert.equal(whois.whois, 'whois.verisign-grs.com', 'WHOIS server doesn\'t match')
});

test(`whoisTld('blog.google')`, async function() {
	let whois = await whoisTld('blog.google')
	assert.equal(whois.domain, 'GOOGLE', 'TLD doesn\'t match')
	assert.equal(whois.whois, 'whois.nic.google', 'WHOIS server doesn\'t match')
});

test(`whoisTld('analytics')`, async function() {
	let whois = await whoisTld('analytics')
	assert.equal(whois.whois, 'whois.nic.analytics', 'WHOIS server doesn\'t match')
	assert.equal(whois.domain, 'ANALYTICS', 'TLD doesn\'t match')
	assert.equal(whois.created, '2015-11-20', 'Created date doesn\'t match')
});

test(`whoisTld('.香港') - IDN`, async function() {
	let whois = await whoisTld('.香港')
	assert.equal(whois.domain, '香港', 'TLD doesn\'t match')
	assert.equal(whois.whois, 'whois.hkirc.hk', 'WHOIS server doesn\'t match')
});

test(`whoisTld('com.au') - SLD`, async function() {
	let whois = await whoisTld('com.au')
	assert.equal(whois.domain, 'AU', 'TLD doesn\'t match')
	assert.equal(whois.whois, 'whois.auda.org.au', 'WHOIS server doesn\'t match')
});

test(`whoisTld('uk') - TLD/SLD match`, async function() {
	const whois1 = await whoisTld('uk')
	const whois2 = await whoisTld('co.uk')
	const whois3 = await whoisTld('google.co.uk')

	assert.equal(whois1.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
	assert.equal(whois2.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
	assert.equal(whois3.whois, 'whois.nic.uk', 'WHOIS server doesn\'t match')
});
