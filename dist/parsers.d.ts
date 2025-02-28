import type { WhoisData, WhoisDataGroup } from './types.ts';
export declare function parseSimpleWhois(whois: string): WhoisData;
export declare function parseDomainWhois(domain: string, whois: string, ignorePrivacy?: boolean): {
    'Domain Status': any[];
    'Name Server': any[];
    text: any[];
};
export declare function whoisDataToGroups(whois: string): {
    comments: string[];
    groups: WhoisDataGroup[];
};
