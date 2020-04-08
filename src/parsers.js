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

const parseDomainWhois = whois => {
	const noData = ['-', 'data protected, not disclosed', 'data redacted', 'redacted for privacy', 'gdpr redacted', 'non-public data', 'gdpr masked', 'not disclosed', 'statutory masking enabled', 'redacted by privacy']
	const renameLabels = {
		'domain name': 'Domain Name',
		domain: 'Domain Name',
		dns: 'Domain Name',
		'idn tag': 'IDN',
		'internationalized domain name': 'IDN',
		nameserver: 'Name Server',
		nameservers: 'Name Server',
		nserver: 'Name Server',
		'name servers': 'Name Server',
		'name server information': 'Name Server',
		'hostname': 'Name Server',
		flags: 'Domain Status',
		status: 'Domain Status',
		'sponsoring registrar iana id': 'Registrar IANA ID',
		organisation: 'Registrar',
		registrar: 'Registrar',
		'registrar name': 'Registrar',
		url: 'Registrar URL',
		'creation date': 'Created Date',
		'registered on': 'Created Date',
		created: 'Created Date',
		'registration time': 'Created Date',
		'registered': 'Created Date',
		'last updated': 'Updated Date',
		changed: 'Updated Date',
		modified: 'Updated Date',
		'last modified': 'Updated Date',
		'registrar registration expiration date': 'Expiry Date',
		'registry expiry date': 'Expiry Date',
		'expires on': 'Expiry Date',
		expires: 'Expiry Date',
		'expiration time': 'Expiry Date',
		'expire date': 'Expiry Date',
		'paid-till': 'Expiry Date',
		'expiry date': 'Expiry Date',
		registrant: 'Registrant Name',
		'registrant contact name': 'Registrant Name',
		'registrant contact email': 'Registrant Email',
		'registrant organisation': 'Registrant Organization',
		'trading as': 'Registrant Organization',
		'registrant state': 'Registrant State/Province',
		'registrant\'s address': 'Registrant Street',
		dnssec: 'DNSSEC',
	}
	const ignoreLabels = ['note', 'notes', 'please note', 'important', 'notice', 'terms of use', 'web-based whois', 'https', 'to', 'registration service provider']
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
		.map(line => line.trim())

	// Fix "label: \n value" format
	lines.forEach((line, index) => {
		if (!line.startsWith('%') && line.endsWith(':')) {
			let addedLabel = false

			for (let i = 1; i <= 5; i++) {
				if (!lines[index + i] || !lines[index + i].length || lines[index + i].includes(': ') || lines[index + i].endsWith(':')) {
					break
				}

				lines[index + i] = line + ' ' + lines[index + i]
			}

			if (addedLabel) {
				lines[index] = ''
			}
		}
	})

	lines.forEach(line => {
		if ((line.includes(': ') || line.endsWith(':')) && !line.startsWith('%') && !line.startsWith(';')) {
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

module.exports.parseSimpleWhois = parseSimpleWhois
module.exports.parseDomainWhois = parseDomainWhois
