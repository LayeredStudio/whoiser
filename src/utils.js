import punycode from 'punycode'

export const splitStringBy = (string, by) => [string.slice(0, by), string.slice(by + 1)]

export const isTld = (tld) => {
	if (tld.startsWith('.')) {
		tld = tld.substring(1)
	}

	//todo use https://nodejs.org/api/url.html#urldomaintoasciidomain
	return /^([a-z]{2,64}|xn[a-z0-9-]{5,})$/i.test(punycode.toASCII(tld))
}

export const isDomain = (domain) => {
	if (domain.endsWith('.')) {
		domain = domain.substring(0, domain.length - 1)
	}

	const labels = punycode.toASCII(domain).split('.').reverse()
	const labelTest = /^([a-z0-9-]{1,64}|xn[a-z0-9-]{5,})$/i

	return (
		labels.length > 1 &&
		labels.every((label, index) => {
			return index ? labelTest.test(label) && !label.startsWith('-') && !label.endsWith('-') : isTld(label)
		})
	)
}
