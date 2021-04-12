type CommonOptions = {
	/** WHOIS server to query. Default: WHOIS server from IANA */
	host?: string
	/** WHOIS server request timeout in ms. Default: `1500` */
	timeout?: number
	/** Return the raw WHOIS result in response. Added to `__raw` */
	raw?: boolean
}

interface Whoiser {
	/**
	 * Get WHOIS data for any internet address
	 *
	 * @param {string|number} query
	 * @param {Object} options
	 * @returns {Promise<*>} Parsed WHOIS server response
	 */
	(query: string | number, options?: CommonOptions & Record<string, string>): Promise<any>


	/**
	 * Get WHOIS data for a TLD
	 *
	 * @param {string} tld Ex. `.net`
	 * @param {Object} options
	 * @returns {Promise<*>} Parsed WHOIS server response
	 */
	tld(tld: string, options?: Omit<CommonOptions, 'host'>): Promise<any>;

	/**
	 * Query a WHOIS server for data
	 *
	 * @param {Object} options
	 * @returns {Promise<string>} Raw WHOIS server response
	 */
	query(options: CommonOptions & {
		query: string;
		/** Low level end of query suffix. Default `\r\n` */
		querySuffix?: string;
	}): Promise<string>

	/**
	 * Get parsed WHOIS data for a domain
	 *
	 * @param domain
	 * @param options
	 */
	domain(
		domain: string,
		options?: CommonOptions & {
			/** How many WHOIS server to query. 1 = registry server (faster), 2 = registry + registrar (more domain details). Default: 2 */
			follow?: number
		}
	): Promise<any>

	/**
	 * Get WHOIS data for a IP
	 *
	 * @param {string} ip
	 * @param {Object} options
	 * @returns {Promise<*>} Parsed WHOIS server response
	 */
	ip(ip: string, options?: CommonOptions): Promise<any>

	/**
	 * Get WHOIS data for an AS number
	 *
	 * @param {string|number} asn
	 * @param {Object} options
	 * @returns {Promise<*>} Parsed WHOIS server response
	 */
	asn(asn: string | number, options?: CommonOptions): Promise<any>;

	/**
	 * Returns a list of all TLDs, [downloaded from IANA](https://www.iana.org/domains/root/db)
	 *
	 * @returns {Promise<string[]>}
	 */
	allTlds(): Promise<string[]>;
}

declare const whoiser: Whoiser;
export = whoiser;
