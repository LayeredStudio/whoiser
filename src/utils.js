const punycode = require('punycode')
const https = require('https')
const splitStringBy = (string, by) => [string.slice(0, by), string.slice(by + 1)]

const requestGetBody = url => {
	return new Promise((resolve, reject) => {
		https
			.get(url, resp => {
				let data = ''
				resp.on('data', chunk => (data += chunk))
				resp.on('end', () => resolve(data))
				resp.on('error', reject)
			})
			.on('error', reject)
	})
}

const isTld = tld => {
	if (tld.startsWith('.')) {
		tld = tld.substring(1)
	}

	return /^([a-z]{2,64}|xn[a-z0-9-]{5,})$/i.test(punycode.toASCII(tld))
}

const isDomain = domain => {
	if (domain.endsWith('.')) {
		domain = domain.substring(0, domain.length - 1)
	}

	const labels = punycode
		.toASCII(domain)
		.split('.')
		.reverse()
	const labelTest = /^([a-z0-9-]{1,64}|xn[a-z0-9-]{5,})$/i

	return (
		labels.length > 1 &&
		labels.every((label, index) => {
			return index ? labelTest.test(label) && !label.startsWith('-') && !label.endsWith('-') : isTld(label)
		})
	)
}

module.exports.splitStringBy = splitStringBy
module.exports.requestGetBody = requestGetBody
module.exports.isTld = isTld
module.exports.isDomain = isDomain
