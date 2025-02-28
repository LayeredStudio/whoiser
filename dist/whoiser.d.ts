import type { TldWhoisResponse, WhoisData } from './types.ts';
export declare function whoisQuery(host: string, query: string, { port, timeout, querySuffix }?: {
    port?: number;
    timeout?: number;
    querySuffix?: string;
}): Promise<string>;
/**
 * TLD WHOIS data, from the [IANA WHOIS](https://www.iana.org/whois) server.
 *
 * @param tld TLD/SLD to query. Example: 'com', '.co.uk'
 * @param timeout
 * @returns Normalized WHOIS data
 * @throws Error if TLD is invalid or not found
 */
export declare function whoisTld(tld: string, timeout?: number): Promise<TldWhoisResponse>;
export declare function whoisDomain(domain: string, { host, timeout, follow, raw, ignorePrivacy }?: {
    host?: any;
    timeout?: number;
    follow?: number;
    raw?: boolean;
    ignorePrivacy?: boolean;
}): Promise<{}>;
export declare function whoisIp(ip: string, { host, timeout }?: {
    host?: any;
    timeout?: number;
}): Promise<WhoisData>;
export declare function whoisAsn(asn: number, { host, timeout }?: {
    host?: any;
    timeout?: number;
}): Promise<WhoisData>;
export declare const firstResult: (whoisResults: any) => any;
