import net from 'node:net'
import { toASCII, toUnicode } from 'punycode'

import type { DomainWhoisOptions, TldWhoisResponse, WhoisData } from './types.ts'
import { parseSimpleWhois, parseDomainWhois, whoisDataToGroups } from './parsers.ts'
import { validatedTld } from './utils.ts'

// Cache WHOIS servers
// Basic list of servers, more will be auto-discovered
let cacheTldWhoisServer = {
	com: 'whois.verisign-grs.com',
	net: 'whois.verisign-grs.com',
	org: 'whois.pir.org',

	// ccTLDs
	ai: 'whois.nic.ai',
	au: 'whois.auda.org.au',
	bz: 'whois.identity.digital',
	co: 'whois.nic.co',
	ca: 'whois.cira.ca',
	do: 'whois.nic.do',
	eu: 'whois.eu',
	gi: 'whois.identity.digital',
	gl: 'whois.nic.gl',
	in: 'whois.registry.in',
	io: 'whois.nic.io',
	it: 'whois.nic.it',
	lc: 'whois.identity.digital',
	me: 'whois.nic.me',
	ro: 'whois.rotld.ro',
	rs: 'whois.rnids.rs',
	so: 'whois.nic.so',
	tr: 'whois.nic.tr',
	us: 'whois.nic.us',
	vc: 'whois.identity.digital',
	ws: 'whois.website.ws',

	agency: 'whois.nic.agency',
	app: 'whois.nic.google',
	biz: 'whois.nic.biz',
	country: 'whois.uniregistry.net', // hardcoded because `whois.iana.org` sometimes returns 'whois.uniregistry.net' or 'whois.nic.country'
	dev: 'whois.nic.google',
	house: 'whois.nic.house',
	health: 'whois.nic.health',
	info: 'whois.nic.info',
	link: 'whois.uniregistry.net',
	live: 'whois.nic.live',
	nyc: 'whois.nic.nyc',
	one: 'whois.nic.one',
	online: 'whois.nic.online',
	shop: 'whois.nic.shop',
	site: 'whois.nic.site',
	xyz: 'whois.nic.xyz',
}

// misspelled whois servers..
const misspelledWhoisServer = {
	//'whois.google.com': 'whois.nic.google',	// Why was this added??
	'www.gandi.net/whois': 'whois.gandi.net',
	'who.godaddy.com/': 'whois.godaddy.com',
	'whois.godaddy.com/': 'whois.godaddy.com',
	'www.nic.ru/whois/en/': 'whois.nic.ru',
	'www.whois.corporatedomains.com': 'whois.corporatedomains.com',
	'www.safenames.net/DomainNames/WhoisSearch.aspx': 'whois.safenames.net',
	'WWW.GNAME.COM/WHOIS': 'whois.gname.com',
}

/**
 * Query a WHOIS server and return the result.
 * @param host WHOIS server hostname
 * @param query Query string
 * @param timeout Timeout duration in milliseconds
 * @returns Result of the WHOIS query
 */
export function whoisQuery(host: string, query: string, timeout: number = 5000): Promise<string> {
	return new Promise((resolve, reject) => {
		let data = ''
		const socket = net.connect({ host, port: 43, family: 4 }, () => socket.write(query + '\r\n'))
		socket.setTimeout(timeout)
		socket.on('data', (chunk) => (data += chunk))
		socket.on('close', () => resolve(data))
		socket.on('timeout', () => socket.destroy(new Error('Timeout')))
		socket.on('error', reject)
	})
}

/**
 * TLD WHOIS data, from the [IANA WHOIS](https://www.iana.org/whois) server.
 * 
 * @param tld TLD/SLD to query. Example: 'com', '.co.uk'
 * @param timeout Timeout for WHOIS query in milliseconds
 * @returns Normalized WHOIS data
 * @throws Error if TLD is invalid or not found
 */
export async function whoisTld(tld: string, timeout: number = 1000): Promise<TldWhoisResponse> {
	tld = validatedTld(tld)

	const whoisData = await whoisQuery('whois.iana.org', tld, timeout)
	const { comments, groups } = whoisDataToGroups(whoisData)
	const groupWithDomain = groups.find((group) => Object.keys(group).includes('domain'))

	if (!groupWithDomain) {
		throw new Error(`TLD "${tld}" not found`)
	}

	const tldResponse: TldWhoisResponse = {
		tld: String(groupWithDomain['domain']),
		organisation: undefined,
		contacts: [],
		nserver: [],
		'ds-rdata': undefined,
		whois: undefined,
		status: 'ACTIVE',
		remarks: '',
		created: '',
		changed: '',
		source: '',
		__comments: comments,
		__raw: whoisData,
	}

	groups.forEach(group => {
		if (Object.keys(group).at(0) === 'organisation') {
			tldResponse.organisation = group
		} else if (Object.keys(group).at(0) === 'contact') {
			tldResponse.contacts.push(group)
		} else {
			for (const key in group) {
				const value = group[key]

				if (value) {
					if (key === 'status') {
						tldResponse.status = value as 'ACTIVE' | 'FORMER'
					} else if (key === 'remarks') {
						tldResponse.remarks = value
					} else if (key === 'created') {
						tldResponse.created = value
					} else if (key === 'changed') {
						tldResponse.changed = value
					} else if (key === 'source') {
						tldResponse.source = value
					} else if (key === 'whois') {
						tldResponse.whois = value
					} else if (key === 'nserver') {
						tldResponse.nserver = value.split('\n').map((ns) => ns.trim())
					} else if (key === 'ds-rdata') {
						tldResponse['ds-rdata'] = value
					}
				}
			}
		}
	})

	return tldResponse
}

/**
 * Get WHOIS data for a domain name.
 * @param domain Domain name to query. Example: 'example.com'
 * @param options Options for querying WHOIS
 * @returns Object containing WHOIS results
 */
export async function whoisDomain(domain: string, options?: DomainWhoisOptions) {
	domain = toASCII(domain)
	const domainTld = domain.split('.').at(-1)
	let results = {}

	// set WHOIS server for TLD
	let host: string | undefined = options?.host || cacheTldWhoisServer[domainTld]

	// find WHOIS server for TLD
	if (!host) {
		const tld = await whoisTld(domainTld)

		if (!tld.whois) {
			throw new Error(`TLD for "${domain}" not supported`)
		}

		host = tld.whois
		cacheTldWhoisServer[domainTld] = tld.whois
	}

	let follow = options?.follow || 1
	const queryFn = options?.whoisQuery || whoisQuery

	// query WHOIS servers for data
	while (host && follow) {
		let query = domain
		let result
		let resultRaw: string

		// hardcoded WHOIS queries..
		if (host === 'whois.denic.de') {
			query = `-T dn ${toUnicode(domain)}`
		} else if (host === 'whois.jprs.jp') {
			query = `${query}/e`
		}

		try {
			resultRaw = await queryFn(host, query, options?.timeout)
			result = parseDomainWhois(domain, resultRaw, options?.ignorePrivacy ?? true)
		} catch (err) {
			result = { error: err.message }
		}

		if (options?.raw) {
			result.__raw = resultRaw
		}

		results[host] = result
		follow--

		// check for next WHOIS server
		let nextWhoisServer =
			result['Registrar WHOIS Server'] ||
			result['Registry WHOIS Server'] ||
			result['ReferralServer'] ||
			result['Registrar Whois'] ||
			result['Whois Server'] ||
			result['WHOIS Server'] ||
			false

		// fill in WHOIS servers when missing
		if (!nextWhoisServer && result['Registrar URL'] && result['Registrar URL'].includes('domains.google')) {
			nextWhoisServer = 'whois.google.com'
		}

		if (nextWhoisServer) {
			// if found, remove protocol and path
			if (nextWhoisServer.includes('://')) {
				let parsedUrl = new URL(nextWhoisServer)
				//todo use parsedUrl.port, if defined
				nextWhoisServer = parsedUrl.hostname
			}

			// check if found server is in misspelled list
			nextWhoisServer = misspelledWhoisServer[nextWhoisServer] || nextWhoisServer

			// check if found server was queried already
			nextWhoisServer = !results[nextWhoisServer] ? nextWhoisServer : false
		}

		host = nextWhoisServer
	}

	return results
}

async function findWhoisServerInIana(query: string) {
	let whoisResult = await whoisQuery('whois.iana.org', query, 1000)
	const { groups } = whoisDataToGroups(whoisResult)

	const groupWithWhois = groups.find((group) => Object.keys(group).includes('whois'))

	return groupWithWhois['whois']
}

/**
 * IP WHOIS data, from the [IANA WHOIS](https://www.iana.org/whois) server.
 * 
 * @param ip IP address to query. Example: '192.0.2.1'
 * @param options Options for WHOIS query
 * @returns Normalized WHOIS data
 * @throws Error if IP is invalid or not found
 */
export async function whoisIp(ip: string, options: { host?: string, timeout?: number } = {}): Promise<WhoisData> {
	if (!net.isIP(ip)) {
		throw new Error(`Invalid IP address "${ip}"`)
	}

	const host = options.host || await findWhoisServerInIana(ip)

	if (!host) {
		throw new Error(`No WHOIS server for "${ip}"`)
	}

	let modifiedQuery = ip

	// hardcoded custom queries..
	if (host === 'whois.arin.net') {
		modifiedQuery = `+ n ${ip}`
	}

	const ipWhoisResult = await whoisQuery(host, modifiedQuery, options.timeout || 1000)

	return parseSimpleWhois(ipWhoisResult)
}

/**
 * ASN WHOIS data, from the [IANA WHOIS](https://www.iana.org/whois) server.
 * @param asn ASN number to query. Example: 12345
 * @param options Options for WHOIS query
 * @returns Normalized WHOIS data
 * @throws Error if ASN is invalid or not found
 */
export async function whoisAsn(asn: number, options: { host?: string, timeout?: number } = {}): Promise<WhoisData> {
	if (asn < 0 || asn > 4294967295) {
		throw new Error(`Invalid ASN number "${asn}"`)
	}

	// find WHOIS server for ASN
	const host = options.host || await findWhoisServerInIana(String(asn));

	if (!host) {
		throw new Error(`No WHOIS server for "${asn}"`)
	}

	let modifiedQuery = String(asn)

	// hardcoded custom queries..
	if (host === 'whois.arin.net') {
		modifiedQuery = `+ a ${asn}`
	}

	const asnWhoisResult = await whoisQuery(host, modifiedQuery, options.timeout || 1000)

	return parseSimpleWhois(asnWhoisResult)
}

export const firstResult = (whoisResults) => {
	const whoisServers = Object.keys(whoisResults)

	return whoisServers.length ? whoisResults[whoisServers[0]] : null
}
