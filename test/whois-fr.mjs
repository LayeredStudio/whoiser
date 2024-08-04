import { strict as assert } from 'node:assert'
import test from 'node:test'

import whoiser from '../index.js'

test('whois for google.fr', async () => {
	const whois = await whoiser.domain('google.fr')

	const whoisServers = Object.keys(whois)

	assert.equal(whoisServers.length, 1, 'Returns 1 WHOIS server')

	const whoisData = whois[whoisServers[0]]

	assert.equal(whoisData['Domain Name'], 'google.fr', 'domain name ok')
	assert.equal(whoisData['Name Server'].length, 4, '4 name servers')
	assert.equal(whoisData['Domain Status'].length, 4, '4 statuses')
	assert.ok(whoisData['Domain Status'].find(s => s === 'serverUpdateProhibited'), '4 name servers')

	// dates
	assert.equal(whoisData['Expiry Date'], '2024-12-30T17:16:48Z')
	assert.equal(whoisData['Created Date'], '2000-07-26T22:00:00Z')
	assert.equal(whoisData['Updated Date'], '2023-12-03T10:43:19.006791Z')

	// registrar
	assert.equal(whoisData['Registrar'], 'MARKMONITOR Inc.')
	assert.equal(whoisData['Registrar URL'], 'http://www.markmonitor.com')

	// registrant
	assert.equal(whoisData['Registrant Name'], 'Google Ireland Holdings Unlimited Company')
	assert.equal(whoisData['Registrant Email'], 'dns-admin@google.com')

	assert.ok(whois, 'No WHOIS data returned')

})
