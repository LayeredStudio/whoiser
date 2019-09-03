const { splitStringBy, isDomain } = require('./utils.js')


const parseSimpleWhois = whois => {
	let data = {}
	let text = []

	const renameLabels = {
		NetRange:	'range',
		inetnum:	'range',
		CIDR:		'route',
		origin:		'asn',
		OriginAS:	'asn',
	}
	const lineToGroup = {
		OrgName:		'organisation',
		organisation:	'organisation',
		OrgAbuseHandle:	'contactAbuse',
		irt:			'contactAbuse',
		RAbuseHandle:	'contactAbuse',
		OrgTechHandle:	'contactTechnical',
		RTechHandle:	'contactTechnical',
		OrgNOCHandle:	'contactNoc',
		RNOCHandle:		'contactNoc',
	}

	if (whois.includes('returned 0 objects') || whois.includes('No match found')) {
		return data
	}

	let resultNum = 0
	let groups = [{}]
	let lastLabel

	whois.split("\n").forEach(line => {

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
						groups[groups.length - 1][label] += "\n" + value
					} else {
						groups[groups.length - 1][label] = value
					}

				} else {
					groups[groups.length - 1][lastLabel] += "\n" + line.trim()
				}

			} else if (Object.keys(groups[groups.length - 1]).length) {

				// if empty line, means another info group starts
				groups.push({})
			}
		}

	})

	groups.filter(group => Object.keys(group).length).forEach(group => {
		const groupLabels = Object.keys(group)
		let isGroup = false

		// check if a label is marked as group
		groupLabels.forEach(groupLabel => {
			if (Object.keys(lineToGroup).includes(groupLabel)) {
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

		if (isGroup) {
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
	const renameLabels = {
		'domain name':	'Domain Name',
		'nameserver':	'Name Server',
		'nserver':		'Name Server',
		'name servers':	'Name Server'
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
		'restrictions',		// found on .co.uk domains
		'queried object',	// found in abc.tech
		'service',			// found in .au domains
		'terms'
	]

	let text = []
	let data = {
		'Domain Status':	[],
		'Name Server':		[]
	}
	let lines = whois.trim().split('\n').map(line => line.trim())

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

			if (renameLabels[label.toLowerCase()]) {
				label = renameLabels[label.toLowerCase()]
			}

			if (data[label] && Array.isArray(data[label])) {
				data[label].push(value)
			} else if (!ignoreLabels.includes(label.toLowerCase()) && !ignoreTexts.some(text => label.toLowerCase().includes(text))) {
				data[label] = data[label] ? data[label] + ' ' + value : value
			} else {
				text.push(line)
			}
		} else {
			text.push(line)
		}

	})

	// remove invalid Name Servers (not valid hostname)
	data['Name Server'] = data['Name Server'].map(nameServer => nameServer.split(' ')[0]).filter(isDomain)

	// remove multiple empty lines
	text = text.join("\n").trim()
	while (text.includes("\n\n\n")) {
		text = text.replace("\n\n\n", "\n")
	}

	data.text = text.split("\n")

	return data
}


module.exports.parseSimpleWhois = parseSimpleWhois
module.exports.parseDomainWhois = parseDomainWhois
