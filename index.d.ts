declare module 'whoiser' {
	interface Options {
		/**
		 * WHOIS server to query.
		 */
		host?: string

		port?: number

		/**
		 * WHOIS server request timeout in ms.
		 *
		 * @default: 1500
		 */
		timeout?: number

		/**
		 * How many WHOIS server to query.
		 * 1 = registry server (faster),
		 * 2 = registry + registrar (more domain details).
		 *
		 * @default: 2
		 */
		follow?: number

		/**
		 * Return the raw WHOIS result in response.
		 * Added to `__raw`
		 */
		raw?: boolean

		query?: string

		/**
		 * Low level end of query suffix.
		 *
		 * @default '\r\n'
		 */
		querySuffix?: string
	}

	type OptionsIp = Pick<Options, 'host' | 'timeout' | 'raw'>
	type OptionsAsn = OptionsIp
	type OptionsQuery = Omit<Options, 'raw' | 'follow'>
	type OptionsTld = Pick<Options, 'timeout' | 'raw'>
	type OptionsDomain = Omit<Options, 'querySuffix' | 'query' | 'port'>
	type OptionsGeneric = OptionsIp | OptionsTld | OptionsDomain

	interface WhoisSearchResult {
		[key: string]: string | Array<string> | WhoisSearchResult
	}

	/**
	 * Returns a list of all TLDs,
	 * [downloaded from IANA](https://www.iana.org/domains/root/db)
	 *
	 * @returns {Promise<string[]>}
	 */
	function allTlds(): Promise<string[]>

	/**
	 * Get WHOIS data for an AS number
	 *
	 * @param {string|number} asn
	 * @param {OptionsAsn} options
	 * @returns {Promise<WhoisSearchResult>} Parsed WHOIS server response
	 */
	function asn(asn: string | number, options?: OptionsAsn): Promise<WhoisSearchResult>

	/**
	 * Get parsed WHOIS data for a domain
	 *
	 * @param {string} domain
	 * @param {OptionsDomain} options
	 * @returns {Promise<WhoisSearchResult>} Parsed WHOIS server response
	 */
	function domain(domain: string, options?: OptionsDomain): Promise<WhoisSearchResult>

	/**
	 * Get WHOIS data for a IP
	 *
	 * @param {string} ip
	 * @param {OptionsIp} options
	 * @returns {Promise<WhoisSearchResult>} Parsed WHOIS server response
	 */
	function ip(ip: string, options?: OptionsIp): Promise<WhoisSearchResult>

	/**
	 * Query a WHOIS server for data
	 *
	 * @param {OptionsQuery} options
	 * @returns {Promise<string>} Raw WHOIS server response
	 */
	function query(options: OptionsQuery): Promise<string>

	/**
	 * Get WHOIS data for a TLD
	 *
	 * @param {string} tld Ex. `.net`
	 * @param {OptionsTld} options
	 * @returns {Promise<WhoisSearchResult>} Parsed WHOIS server response
	 */
	function tld(tld: string, options?: OptionsTld): Promise<WhoisSearchResult>

	/**
	 * Tries to guess query type and get WHOIS data
	 *
	 * @param {string} query
	 * @param {Options} options
	 * @returns {Promise<WhoisSearchResult>} Parsed WHOIS server response
	 */
	function whoiser(query: string, options?: OptionsGeneric): Promise<WhoisSearchResult>

	export = whoiser
}
