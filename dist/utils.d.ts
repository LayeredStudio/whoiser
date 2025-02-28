export declare function splitStringBy(string: string, by: number): [string, string];
/**
 * Check if a string is a valid TLD, and return it in canonical form.
 *
 * @param tld
 * @returns The normalized TLD
 * @throws If the TLD is invalid
 */
export declare function validatedTld(tld: string): string;
export declare function isTld(tld: string): boolean;
export declare function isDomain(domain: string): boolean;
