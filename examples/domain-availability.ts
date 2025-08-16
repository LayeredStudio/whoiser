import { whoisDomain, firstResult } from '../src/whoiser.ts'

const domains = ['an-available-domain.com', 'x.com', 'should-not-be-registered.com']
const domainName = domains[~~(Math.random() * domains.length)]

// retrieve WHOIS info from Registrar WHOIS servers
const domainWhois = await whoisDomain(domainName, { follow: 1 })

const firstDomainWhois = firstResult(domainWhois)
const firstTextLine = firstDomainWhois.text?.length ? firstDomainWhois.text[0] : ''

let domainAvailability = 'unknown'

if (firstDomainWhois['Domain Name'] && firstDomainWhois['Domain Name'].toLowerCase() === domainName) {
	domainAvailability = 'registered'
} else if (firstTextLine.toLowerCase().includes(`no match for "${domainName}"`)) {
	domainAvailability = 'available'
}

if (domainAvailability === 'available') {
	console.log(`🟢 "${domainName}" is available for registration right now!`)
} else if (domainAvailability === 'registered') {
	console.log(`🔷 Domain "${domainName}" is registered at "${firstDomainWhois.Registrar}"`)
	console.log('Registered on', firstDomainWhois['Created Date'])
	console.log('Expiration date is', firstDomainWhois['Expiry Date'])
	console.log('Nameservers:', firstDomainWhois['Name Server'])
} else {
	console.log(`⚠️ Domain "${domainName}" is "${domainAvailability}"`)
}
