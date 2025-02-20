
export interface WhoisDataGroup {
	[key: string]: string
}

export interface WhoisData {
	[key: string]: string | string[] | WhoisDataGroup | {[key: string]: WhoisDataGroup} | undefined
	contacts?: {[key: string]: WhoisDataGroup}
	__comments: string[]
	__raw: string
}

/**
 * TLD Whois response, from iana.org
 */
export interface TldWhoisResponse {
	tld: string
	organisation?: WhoisDataGroup
	contacts: WhoisDataGroup[]
	nserver: string[]
	'ds-rdata'?: string
	whois?: string
	status: 'ACTIVE' | 'FORMER'
	remarks: string
	created: string
	changed: string
	source: string
	__comments: string[]
	__raw: string
}
