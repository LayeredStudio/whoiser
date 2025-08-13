import { toASCII } from 'punycode-esm'

export function splitStringBy(string: string, by: number): [string, string] {
	return [string.slice(0, by), string.slice(by + 1)]
}

/**
 * Check if a string is a valid TLD, and return it in canonical form.
 * 
 * @param tld 
 * @returns The normalized TLD
 * @throws If the TLD is invalid
 */
export function validatedTld(tld: string): string {
	tld = tld.trim().toLowerCase()

	if (tld.startsWith('.')) {
		tld = tld.substring(1)
	}

	if (tld.endsWith('.')) {
		tld = tld.slice(0, -1)
	}

	const labelTest = /^([a-z]{2,64}|xn[a-z0-9-]{5,})$/
	const labels = tld.split('.').map(label => toASCII(label))

	if (!labels.every(label => labelTest.test(label))) {
		throw new Error(`Invalid TLD "${tld}"`)
	}

	//return labels.join('.')
	return tld
}

export function isTld(tld: string): boolean {
	if (tld.startsWith('.')) {
		tld = tld.substring(1)
	}

	//todo use https://nodejs.org/api/url.html#urldomaintoasciidomain
	return /^([a-z]{2,64}|xn[a-z0-9-]{5,})$/i.test(toASCII(tld))
}

export function isDomain(domain: string): boolean {
	if (domain.endsWith('.')) {
		domain = domain.substring(0, domain.length - 1)
	}

	const labels = toASCII(domain).split('.').reverse()
	const labelTest = /^([a-z0-9-]{1,64}|xn[a-z0-9-]{5,})$/i

	return (
		labels.length > 1 &&
		labels.every((label, index) => {
			return index ? labelTest.test(label) && !label.startsWith('-') && !label.endsWith('-') : isTld(label)
		})
	)
}
