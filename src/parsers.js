const { splitStringBy, isDomain } = require('./utils.js')

const parseSimpleWhois = whois => {
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

	whois.split('\n').forEach(line => {
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
					const [label, value] = splitStringBy(line, line.indexOf(':')).map(info => info.trim())
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
		.filter(group => Object.keys(group).length)
		.forEach(group => {
			const groupLabels = Object.keys(group)
			let isGroup = false

			// check if a label is marked as group
			groupLabels.forEach(groupLabel => {
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
				for (key in group) {
					const label = renameLabels[key] || key
					data[label] = group[key]
				}
			}
		})

	// Append the WHOIS comments
	data.text = text

	return data
}

const parseDomainWhois = (domain, whois) => {
	const noData = ['-', '.', 'data protected', 'not disclosed', 'data protected, not disclosed', 'data redacted', 'not available', 'redacted for privacy', 'gdpr redacted', 'non-public data', 'gdpr masked', 'statutory masking enabled', 'redacted by privacy', 'not applicable']
	const renameLabels = {
		'domain name': 'Domain Name',
		domain: 'Domain Name',
		'idn tag': 'IDN',
		'internationalized domain name': 'IDN',
		nameserver: 'Name Server',
		nameservers: 'Name Server',
		nserver: 'Name Server',
		'name servers': 'Name Server',
		'name server information': 'Name Server',
		dns: 'Name Server',
		'nserver..............': 'Name Server',
		'hostname': 'Name Server',
		flags: 'Domain Status',
		status: 'Domain Status',
		'registration status': 'Domain Status',
		'sponsoring registrar iana id': 'Registrar IANA ID',
		organisation: 'Registrar',
		registrar: 'Registrar',
		'registrar name': 'Registrar',
		'registrar............': 'Registrar',
		'record maintained by': 'Registrar',
		'sponsoring registrar': 'Registrar',
		url: 'Registrar URL',
		'registrar website': 'Registrar URL',
		'www..................': 'Registrar URL',
		'web': 'Registrar URL',
		'creation date': 'Created Date',
		'registered on': 'Created Date',
		'registration date': 'Created Date',
		'relevant dates registered on': 'Created Date',
		created: 'Created Date',
		'registration time': 'Created Date',
		'registered': 'Created Date',
		'created..............': 'Created Date',
		'domain registered': 'Created Date',
		'last updated': 'Updated Date',
		changed: 'Updated Date',
		modified: 'Updated Date',
		'modification date': 'Updated Date',
		'last modified': 'Updated Date',
		'relevant dates last updated': 'Updated Date',
		'registrar registration expiration date': 'Expiry Date',
		'registry expiry date': 'Expiry Date',
		'expires on': 'Expiry Date',
		expires: 'Expiry Date',
		'expiration time': 'Expiry Date',
		'expire date': 'Expiry Date',
		'expiration date': 'Expiry Date',
		'expires..............': 'Expiry Date',
		'paid-till': 'Expiry Date',
		'expiry date': 'Expiry Date',
		'expire': 'Expiry Date',
		'relevant dates expiry date': 'Expiry Date',
		'record will expire on': 'Expiry Date',
		registrant: 'Registrant Name',
		'registrant contact name': 'Registrant Name',
		'registrant contact email': 'Registrant Email',
		'registrant organisation': 'Registrant Organization',
		'trading as': 'Registrant Organization',
		'registrant state': 'Registrant State/Province',
		'registrant\'s address': 'Registrant Street',
		dnssec: 'DNSSEC',
	}
	const ignoreLabels = ['note', 'notes', 'please note', 'important', 'notice', 'terms of use', 'web-based whois', 'https', 'to', 'registration service provider', 'you acknowledge that']
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

	let text = []
	let data = {
		'Domain Status': [],
		'Name Server': [],
	}
	let lines = whois
		.trim()
		.split('\n')
		.map(line => line.replace("\t", '  '))


	if (domain.endsWith('.uk') || domain.endsWith('.be') || domain.endsWith('.nl') || domain.endsWith('.eu')) {
		lines = handleMultiLines(lines)
	}

	lines = lines.map(l => l.trim())

	lines.forEach(line => {
		if ((line.includes(': ') || line.endsWith(':')) && !line.startsWith('%') && !line.startsWith(';') && !line.startsWith('*')) {
			let [label, value] = splitStringBy(line, line.indexOf(':')).map(info => info.trim())

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
			if (noData.includes(value.toLowerCase())) {
				value = ''
			}

			if (data[label] && Array.isArray(data[label])) {
				data[label].push(value)
			} else if (!ignoreLabels.includes(label.toLowerCase()) && !ignoreTexts.some(text => label.toLowerCase().includes(text))) {
				data[label] = data[label] && data[label] !== value ? data[label] + ' ' + value : value
			} else {
				text.push(line)
			}
		} else {
			text.push(line)
		}
	})

	// remove invalid Name Servers (not valid hostname)
	data['Name Server'] = data['Name Server']
		.map(nameServer => nameServer.split(' '))
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

// Fix "label: \n value" format
const handleMultiLines = lines => {
	lines.forEach((line, index) => {

		// if line is just a WHOIS label ending with ":", then verify next lines
		if (!line.startsWith('*') && !line.startsWith('%') && line.trim().endsWith(':')) {
			let addedLabel = false

			// Check next lines
			for (let i = 1; i <= 5; i++) {

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

module.exports.parseSimpleWhois = parseSimpleWhois
module.exports.parseDomainWhois = parseDomainWhois
