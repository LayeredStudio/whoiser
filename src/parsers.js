const { splitStringBy, isDomain } = require('./utils.js')

const parseSimpleWhois = (whois) => {
	let data = {}
	let text = []

	const renameLabels = {
		NetRange: 'range',
		inetnum: 'range',
		CIDR: 'route',
		origin: 'asn',
		OriginAS: 'asn',
	}
	const lineToGroup = {
		contact: 'contact',
		OrgName: 'organisation',
		organisation: 'organisation',
		OrgAbuseHandle: 'contactAbuse',
		irt: 'contactAbuse',
		RAbuseHandle: 'contactAbuse',
		OrgTechHandle: 'contactTechnical',
		RTechHandle: 'contactTechnical',
		OrgNOCHandle: 'contactNoc',
		RNOCHandle: 'contactNoc',
	}

	if (whois.includes('returned 0 objects') || whois.includes('No match found')) {
		return data
	}

	let resultNum = 0
	let groups = [{}]
	let lastLabel

	whois.split('\n').forEach((line) => {
		// catch comment lines
		if (line.startsWith('%') || line.startsWith('#')) {
			// detect if an ASN or IP has multiple WHOIS results
			if (line.includes('# start')) {
				// nothing
			} else if (line.includes('# end')) {
				resultNum++
			} else {
				text.push(line)
			}
		} else if (resultNum === 0) {
			// for the moment, parse only first WHOIS result

			if (line) {
				if (line.includes(':')) {
					const [label, value] = splitStringBy(line, line.indexOf(':')).map((info) => info.trim())
					lastLabel = label

					// 1) Filter out unnecessary info, 2) then detect if the label is already added to group
					if (value.includes('---')) {
						// do nothing with useless data
					} else if (groups[groups.length - 1][label]) {
						groups[groups.length - 1][label] += '\n' + value
					} else {
						groups[groups.length - 1][label] = value
					}
				} else {
					groups[groups.length - 1][lastLabel] += '\n' + line.trim()
				}
			} else if (Object.keys(groups[groups.length - 1]).length) {
				// if empty line, means another info group starts
				groups.push({})
			}
		}
	})

	groups
		.filter((group) => Object.keys(group).length)
		.forEach((group) => {
			const groupLabels = Object.keys(group)
			let isGroup = false

			// check if a label is marked as group
			groupLabels.forEach((groupLabel) => {
				if (!isGroup && Object.keys(lineToGroup).includes(groupLabel)) {
					isGroup = lineToGroup[groupLabel]
				}
			})

			// check if a info group is a Contact in APNIC result
			// @Link https://www.apnic.net/manage-ip/using-whois/guide/role/
			if (!isGroup && groupLabels.includes('role')) {
				isGroup = 'Contact ' + group.role.split(' ')[1]
			} else if (!isGroup && groupLabels.includes('person')) {
				isGroup = 'Contact ' + group['nic-hdl']
			}

			if (isGroup === 'contact') {
				data.contacts = data.contacts || {}
				data.contacts[group['contact']] = group
			} else if (isGroup) {
				data[isGroup] = group
			} else {
				for (const key in group) {
					const label = renameLabels[key] || key
					data[label] = group[key]
				}
			}
		})

	// Append the WHOIS comments
	data.text = text

	return data
}

const parseDomainWhois = (domain, whois, ignorePrivacy) => {
	// Text saying there's no useful data in a field
	const noData = [
		'-',
		'.',
		'n/a',
		'no data',
		'redacted',
		'privado',
		'datos privados',
		'data protected',
		'not disclosed',
		'data protected, not disclosed',
		'data redacted',
		'not disclosed not disclosed',
		'not disclosed! visit www.eurid.eu for webbased whois.',
		'not available',
		'redacted for privacy',
		'redacted | eu data subject',
		'gdpr redacted',
		'non-public data',
		'gdpr masked',
		'statutory masking enabled',
		'redacted by privacy',
		'not applicable',
		'na',
		'redacted for privacy purposes',
		'redacted | eu registrar',
		'registration private',
		'none',
		'redacted.forprivacy',
		'redacted | registry policy',
		'redacted for gdpr privacy',
		'redacted for gdpr',
		'redacted redacted',
		'not available from registry',
		'hidden upon user request',
	]

	// WHOIS labels to rename. "From" must be lowercase
	// from -> to
	const renameLabels = {
		'domain name': 'Domain Name',
		domain: 'Domain Name',
		'domain...............': 'Domain Name', // found in .ax
		'idn tag': 'IDN',
		'internationalized domain name': 'IDN',
		nameserver: 'Name Server',
		nameservers: 'Name Server',
		nserver: 'Name Server',
		'name servers': 'Name Server',
		'name server information': 'Name Server',
		dns: 'Name Server',
		'nserver..............': 'Name Server', // found in .ax
		hostname: 'Name Server',
		'domain nameservers': 'Name Server',
		'domain servers in listed order': 'Name Server', // found in .ly
		'domain servers': 'Name Server', // found in .tr
		'name servers dns': 'Name Server', // found in .mx
		flags: 'Domain Status',
		status: 'Domain Status',
		state: 'Domain Status', // found in .ru
		'registration status': 'Domain Status',
		'eppstatus': 'Domain Status', // found in .fr
		'sponsoring registrar iana id': 'Registrar IANA ID',
		organisation: 'Registrar',
		registrar: 'Registrar',
		'registrar name': 'Registrar',
		'registrar organization': 'Registrar',
		'registrar............': 'Registrar', // found in .ax
		'record maintained by': 'Registrar',
		'sponsoring registrar': 'Registrar',
		'registrar organization name': 'Registrar', // found in .tr
		url: 'Registrar URL',
		'registrar website': 'Registrar URL',
		'registrar web': 'Registrar URL', // found in .it
		'www..................': 'Registrar URL', // found in .ax
		'mnt-by': 'Registrar ID', // found in .ua
		'creation date': 'Created Date',
		'registered on': 'Created Date',
		'registration date': 'Created Date',
		'relevant dates registered on': 'Created Date',
		created: 'Created Date',
		'created on': 'Created Date', // found in .mx
		'additional info created on..............': 'Created Date', // found in .tr
		'registration time': 'Created Date',
		registered: 'Created Date',
		'created..............': 'Created Date', // found in .ax
		'domain registered': 'Created Date',
		'registered date': 'Created Date', // found in .co.jp
		'last updated': 'Updated Date',
		changed: 'Updated Date',
		modified: 'Updated Date',
		updated: 'Updated Date', // found in .ly
		'modification date': 'Updated Date',
		'last modified': 'Updated Date',
		'relevant dates last updated': 'Updated Date', // found in .uk, .co.uk
		'last updated on': 'Updated Date', // found in .mx
		'last update': 'Updated Date', // found in .co.jp
		'last-update': 'Updated Date', // found in .fr
		'registrar registration expiration date': 'Expiry Date',
		'registry expiry date': 'Expiry Date',
		'expires on': 'Expiry Date',
		expires: 'Expiry Date',
		'expiration time': 'Expiry Date',
		'expire date': 'Expiry Date',
		'expiration date': 'Expiry Date',
		'expires..............': 'Expiry Date', // found in .ax
		'additional info expires on..............': 'Expiry Date', // found in .tr
		'paid-till': 'Expiry Date',
		'expiry date': 'Expiry Date',
		expire: 'Expiry Date',
		'relevant dates expiry date': 'Expiry Date', // found in .uk, .co.uk
		'record will expire on': 'Expiry Date',
		expired: 'Expiry Date', // found in .ly
		'registry registrantid': 'Registry Registrant ID', // found in .ai
		registrant: 'Registrant Name', // found in .ai
		'registrant contact': 'Registrant Name',
		'registrant contact name': 'Registrant Name',
		registrantname: 'Registrant Name', // found in .ai
		'registrant person': 'Registrant Name', // found in .ua
		'registrant email': 'Registrant Email', // found in .ua
		'registrant e-mail': 'Registrant Email', // found in .fr
		'registrant contact email': 'Registrant Email',
		registrantemail: 'Registrant Email', // found in .ai
		registrantstreet: 'Registrant Street', // found in .ai
		registrantcity: 'Registrant City', // found in .ai
		registrantcountry: 'Registrant Country', // found in .ai
		'registrant country': 'Registrant Country', // found in .fr
		'registrant organisation': 'Registrant Organization',
		registrantphone: 'Registrant Phone',
		'trading as': 'Registrant Organization', // found in .uk, .co.uk
		org: 'Registrant Organization', // found in .ru
		'registrant state': 'Registrant State/Province',
		"registrant's address": 'Registrant Street',
		dnssec: 'DNSSEC',
	}
	const ignoreLabels = [
		'note',
		'notes',
		'please note',
		'important',
		'notice',
		'terms of use',
		'web-based whois',
		'https',
		'to',
		'registration service provider',
		'you acknowledge that',
	]
	const ignoreTexts = [
		'more information',
		'lawful purposes',
		'to contact',
		'use this data',
		'register your domain',
		'copy and paste',
		'find out more',
		'this',
		'please',
		'important',
		'prices',
		'payment',
		'you agree',
		'restrictions', // found on .co.uk domains
		'queried object', // found in abc.tech
		'service', // found in .au domains
		'terms',
	]

	let colon = ': '
	let text = []
	let data = {
		'Domain Status': [],
		'Name Server': [],
	}
	let lines = whois
		.trim()
		.split('\n')
		.map((line) => line.replace('\t', '  '))

	// Parse WHOIS info for specific TLDs

	if (
		domain.endsWith('.uk') ||
		domain.endsWith('.be') ||
		domain.endsWith('.nl') ||
		domain.endsWith('.eu') ||
		domain.endsWith('.ly') ||
		domain.endsWith('.mx') ||
		domain.endsWith('.gg') ||
		domain.endsWith('.je') ||
		domain.endsWith('.as')
	) {
		lines = handleMultiLines(lines)
	}

	if (domain.endsWith('.gg') || domain.endsWith('.je') || domain.endsWith('.as')) {
		lines = handleMissingColons(lines)
	}

	if (domain.endsWith('.ua')) {
		lines = handleDotUa(lines)
		colon = ':'
	}

	if (domain.endsWith('.jp')) {
		lines = handleJpLines(lines)
	}

	if (domain.endsWith('.it')) {
		lines = handleDotIt(lines)
	} else if (domain.endsWith('.fr')) {
		lines = handleDotFr(lines)
	}

	if (domain.endsWith('.tr')) {
		lines = handleDotTr(lines)
	}

	lines = lines.map((l) => l.trim())

	lines.forEach((line) => {
		if ((line.includes(colon) || line.endsWith(':')) && !line.startsWith('%') && !line.startsWith(';') && !line.startsWith('*')) {
			let [label, value] = splitStringBy(line, line.indexOf(':')).map((info) => info.trim())

			// fix whois line with double color, ex: "Label:: value"
			if (value.startsWith(':')) {
				value = value.slice(1)
			}

			value = value.trim()

			// rename labels to more common format
			if (renameLabels[label.toLowerCase()]) {
				label = renameLabels[label.toLowerCase()]
			}

			// remove redacted data
			if (ignorePrivacy && noData.includes(value.toLowerCase())) {
				value = ''
			}

			if (data[label] && Array.isArray(data[label])) {
				data[label].push(value)
			} else if (!ignoreLabels.includes(label.toLowerCase()) && !ignoreTexts.some((text) => label.toLowerCase().includes(text))) {
				// WHOIS field already exists, if so append data
				if (data[label] && data[label] !== value) {
					data[label] = `${data[label]} ${value}`.trim()
				} else {
					data[label] = value
				}
			} else {
				text.push(line)
			}
		} else {
			text.push(line)
		}
	})

	// remove invalid Name Servers (not valid hostname)
	data['Name Server'] = data['Name Server']
		.map((nameServer) => nameServer.split(' '))
		.flat()
		.filter(isDomain)

	// filter out empty status lines
	data['Domain Status'] = data['Domain Status'].filter(Boolean)

	// remove multiple empty lines
	text = text.join('\n').trim()
	while (text.includes('\n\n\n')) {
		text = text.replace('\n\n\n', '\n')
	}

	data.text = text.split('\n')

	return data
}

const handleDotTr = (lines) => {
	lines = lines.filter((line) => line.trim() !== '') // Remove blank lines

	const registrantLines = ['Name', undefined, undefined, undefined, undefined] // No clue what the other 4 fields are, all domains have them hidden
	const replacement = []
	let section = ''
	let sectionLine = 0

	for (let line of lines) {
		line = line.replace(/\s+/g, ' ').replace(' :', ':').trim()

		if (line.startsWith('** Domain')) {
			// Keep line for domain name/nameservers
			line = line.replace('** ', '')
		} else if (line.includes('** ')) {
			// Start new section
			section = line.replace(':', '').replace('** ', '').trim()
			sectionLine = 0
			continue
		} else if (section === 'Registrant') {
			// Add registrant info
			if (!registrantLines[sectionLine]) continue

			line = `Registrant ${registrantLines[sectionLine]}: ${line}`
			sectionLine++
		} else if (!line.includes(': ')) {
			// Add multi-line information to one line (nameservers and address)
			replacement[replacement.length - 1] += ` ${line}`
			continue
		} else if (section) {
			// Append section name to each line
			line = `${section} ${line}`
		}

		// Remove period at end of dates
		if (section === 'Additional Info') {
			line = line.replace(/\.$/, '')
		}

		replacement.push(line)
	}

	return replacement
}

const handleDotUa = (lines) => {
	const types = ['Registrar', 'Registrant', 'Admin', 'Technical']
	let flag = ''
	lines.forEach((line, index) => {
		if (line.startsWith('%') && types.some((v) => line.includes(v))) {
			flag = line
				.substring(1, line.length - 1)
				.trim()
				.toLowerCase()
		} else if (!line.startsWith('%') && line.includes(': ')) {
			if (line.startsWith('registrar')) line = 'id'
			lines[index] = flag + ' ' + line
		}
	})
	return lines
}

const handleDotIt = (lines) => {
	let section = ''
	const replacement = []

	for (let line of lines) {
		// Ignore comments and empty lines
		if (line.startsWith('*') || line === '') {
			continue
		}

		// Collapse whitespace
		const collapsed = line.replace(/\s+/g, ' ').trim()

		// Check for top-level values and new section indicators
		if (/^[^\s]/.test(line)) {
			if (line.includes(':')) {
				replacement.push(collapsed)
			} else {
				// Special handling for "Nameservers" section
				if (line === 'Nameservers') {
					section = 'Name Server:'
				} else {
					section = collapsed
				}
			}
		}

		// Make sure sub-section lines are properly labeled
		if (/^\s{2}[^\s]/.test(line)) {
			// New sub-section
			replacement.push(`${section} ${collapsed}`)
		} else if (/^\s{4}/.test(line)) {
			// Continuation of previous line
			replacement[replacement.length - 1] += `, ${collapsed}`
		}
	}

	return replacement
}

// Fix "label: \n value" format
const handleMultiLines = (lines) => {
	lines.forEach((line, index) => {
		// if line is just a WHOIS label ending with ":", then verify next lines
		if (!line.startsWith('*') && !line.startsWith('%') && line.trim().endsWith(':')) {
			let addedLabel = false

			// Check next lines
			for (let i = 1; i <= 8; i++) {
				// if no line or empty line
				if (!lines[index + i] || !lines[index + i].trim().length) {
					break
				}

				// if tabbed line or line with value only, prefix the line with main label
				if ((lines[index + i].startsWith('  ') && lines[index + i].includes(': ')) || !lines[index + i].endsWith(':')) {
					let label = line.trim()

					if (lines[index + i].includes(':') && label.endsWith(':')) {
						label = label.slice(0, -1)
					}

					lines[index + i] = label + ' ' + lines[index + i].replace('\t', ' ').trim()
					addedLabel = true
				}
			}

			// remove this line if it was just a label for other lines
			if (addedLabel) {
				lines[index] = ''
			}
		}
	})

	return lines
}

// Handle formats like this:
// [Name Server]                   ns1.jprs.jp
// [Name Server]                   ns2.jprs.jp
const handleJpLines = (lines) => {
	const ret = []

	while (lines.length > 0) {
		let line = lines.shift()

		// handle lines that start with "a. [label]"
		if (/^[a-z]. \[/.test(line)) {
			line = line.replace(/^[a-z]. \[/, '[')
		}

		if (line.startsWith('[ ')) {
			// skip
		} else if (line.startsWith('[')) {
			ret.push(line)
		} else if (line.startsWith(' ')) {
			const prev = ret.pop()
			ret.push(prev + '\n' + line.trim())
		} else {
			// skip
		}
	}
	return ret.map((line) => line.replace(/\[(.*?)\]/g, '$1:'))
}

/**
 * Normalize WHOIS data for .fr ccTld, make it look more like gTLDs
 * 
 * @param {string[]} lines 
 * @returns
 */
function handleDotFr(lines) {
	const groups = []
	let group = []
	const finalLines = []

	// split data in groups
	lines.forEach(line => {
		if (line.startsWith('%')) {
			finalLines.push(line)
		} else if (!line.trim().length && group.length) {
			// start new group
			groups.push(group)
			group = []
		} else if (line.trim().length && !line.startsWith('source')) {
			group.push(splitStringBy(line, line.indexOf(':')).map(str => str.trim()))
		}
	})

	if (group.length) {
		groups.push(group)
	}

	groups.forEach(gr => {
		if (gr[0][0] === 'domain') {
			// group with domain info
			gr.forEach(line => {
				if (line[0] !== 'status') {
					finalLines.push(line.join(': '))
				}
			})
		} else if (gr[0][0] === 'registrar') {
			// group with Registrar info
			gr.forEach(([label, value]) => {
				if (label === 'registrar') {
					finalLines.push(`${label}: ${value}`)
				} else {
					finalLines.push(`registrar ${label}: ${value}`)
				}
			})
		} else if (gr[0][0] === 'nic-hdl') {
			let contactType = ''
			const contactTypeLine = finalLines.find(line => line.includes(gr[0][1]))

			if (contactTypeLine.startsWith('admin-c')) {
				contactType = 'admin'
			} else if (contactTypeLine.startsWith('holder-c')) {
				contactType = 'registrant'
			} else if (contactTypeLine.startsWith('tech-c')) {
				contactType = 'technical'
			}

			// group with contact info
			gr.forEach(([label, value]) => {
				if (label === 'nic-hdl') {
					finalLines.push(`${contactType} registry id: ${value}`)
				} else {
					finalLines.push(`${contactType} ${label}: ${value}`)
				}
			})
		} else {
			gr.forEach(line => {
				finalLines.push(line.join(': '))
			})
		}

	})

	return finalLines
}

// Handle formats like this:
// Registrar Gandi SAS
const handleMissingColons = (lines) => {
	lines.forEach((line, index) => {
		if (line.startsWith('Registrar ')) {
			lines[index] = line.replace('Registrar ', 'Registrar: ')
		}
	})

	return lines
}

module.exports.parseSimpleWhois = parseSimpleWhois
module.exports.parseDomainWhois = parseDomainWhois
