# Whoiser change log

#### 1.17.0 - 21 April 2023

- Fixed - Code syntax to allow strict [#99](https://github.com/LayeredStudio/whoiser/pull/99)
- Updated - Detect more redacted data in domain WHOIS

#### 1.16.0 - 6 February 2023

- Added - Option to show/hide domain WHOIS protected data [#96](https://github.com/LayeredStudio/whoiser/pull/96)
- Fixed - Include `punycode` from userland lib [a2ee6f9](https://github.com/LayeredStudio/whoiser/commit/a2ee6f9d338ff44aeaf57d61adde3df454ff2d07)
- Fixed - Query WHOIS for .de with umlaut in both ASCII/Unicode [5a7ffd1](https://github.com/LayeredStudio/whoiser/commit/5a7ffd133a4a11d8fd701b4b4d65a033c81012a8)

#### 1.15.0 - 4 February 2023

- Updated - Improved .it parsing, preserve date structure and more [#92](https://github.com/LayeredStudio/whoiser/pull/92)
- Updated - Merge/normalize more WHOIS domain labels
- Fixed - Uses raw domain for .de TLD in `whoisDomain` [#95](https://github.com/LayeredStudio/whoiser/pull/95)
- Fixed - Query more sources for TLD whois server [#86](https://github.com/LayeredStudio/whoiser/pull/86)

#### 1.14.0 - 14 January 2023

- Added - Support for third level domains [#80](https://github.com/LayeredStudio/whoiser/pull/80)
- Added - Additional support for TLDs not in the IANA database [#80](https://github.com/LayeredStudio/whoiser/pull/80)
- Fixed - Follow RIPE referrals [#80](https://github.com/LayeredStudio/whoiser/pull/80)
- Fixed - Parse .gg, .je, and .as whois data correctly [#80](https://github.com/LayeredStudio/whoiser/pull/80)
- Fixed - Improved parser for .it whois data [#84](https://github.com/LayeredStudio/whoiser/pull/84)

#### 1.13.2 - 28 November 2022

- Updated - Include more WHOIS servers in lib, speeds-up domain WHOIS queries
- Updated - Detect & remove more redacted WHOIS text

#### 1.13.1 - 5 December 2021

- Added - Included WHOIS server for `.us` & `.xyz`

#### 1.13.0 - 25 June 2021

- Updated - TypeScript Types [#41](https://github.com/LayeredStudio/whoiser/pull/41)
- Updated - Cache more TLD WHOIS servers (.ai, .app, .io, .nyc)
- Updated - Detect & remove more redacted whois text

#### 1.12.0 - 9 June 2021

- Added - Utility function `whoiser.firstResult()` to extract first WHOIS result
- Updated - TypeScript Types [#36](https://github.com/LayeredStudio/whoiser/pull/36) (thanks to @AKorezin)
- Removed - Automated tests for NodeJS 12

#### 1.11.0 - 12 April 2021

- Added - TypeScript Types [#34](https://github.com/LayeredStudio/whoiser/pull/34) (thanks to @AlexXanderGrib)
- Updated - Parse WHOIS for .jp domains [#35](https://github.com/LayeredStudio/whoiser/pull/35) (thanks to @kuriyama)

#### 1.10.0 - 3 April 2021
- Updated - Parse WHOIS for co.ua/biz.ua domains; improve parsing for other .ua domains [#32](https://github.com/LayeredStudio/whoiser/pull/32) (thanks to @EPolishchuk)
- Updated - Detect & remove more redacted whois text
- Fixed - Trim whitespace from whois value when appending data

#### 1.9.2 - 7 Dec 2020
- Updated - Parse WHOIS for .mx domains

#### 1.9.1 - 10 Nov 2020
- Added - Cache IP of WHOIS servers (experiment to see if faster)
- Updated - Detect & remove more redacted whois text

#### 1.9.0 - 11 Sep 2020
- Removed - Node.js 10 support, removed array-flat polyfill
- Updated - Detect & remove more redacted whois text

#### 1.8.1 - 13 July 2020
- Updated - Improved parsing for .ly domains WHOIS
- Updated - Detect & remove more redacted whois text

#### 1.8.0 - 9 July 2020
- Updated - Improved parsing for .nl, .ax domain WHOIS [#18](https://github.com/LayeredStudio/whoiser/pull/18)
- Updated - Detect & remove more redacted whois text

#### 1.7.4 - 2 July 2020
- Updated - Detect & remove more redacted whois text

#### 1.7.3 - 16 May 2020
- Updated - WHOIS date fields for .uk domains are now converted to common format

#### 1.7.2 - 16 May 2020
- Fixed - Enable WHOIS multi line parser for .uk TLD

#### 1.7.1 - 16 May 2020
- Fixed - Apply multi lines fix only for TLDs that need it

#### 1.7.0 - 16 May 2020
- Updated - Improved WHOIS parsing for multi line info (for .be, .eu domains and hopefully others)
- Updated - Detect & remove more redacted whois text

#### 1.6.6 - 8 April 2020
- Updated - detect more redacted whois text
- Fixed - Parse WHOIS lines with double colon #6

#### 1.6.2 - 19 Nov 2019
- Updated - Merge more WHOIS domain labels
- Fixed - Return contact info for TLD WHOIS

#### 1.6.1 - 13 Nov 2019
- Updated - Merge more WHOIS domain labels

#### 1.6.0 - 10 Nov 2019
- Added - Option to return raw WHOIS data #2
- Updated - Merge more domain WHOIS labels
- Updated - Moved JS code to src dir

#### 1.5.0 - 1 Nov 2019
- Updated - Renamed domain WHOIS labels to make them consistent across WHOIS servers
- Fixed - Misspelled WHOIS servers

#### 1.4.0 - 25 Jul 2019
- Updated - Unified code for IP & ASN query, as it's the same
- Updated - Parse raw whois info for IP & ASN, returns object with same labels across whois servers

#### 1.3.0 - 23 Feb 2019
- Updated - TLD & domain validator functions
- Updated - More ignored keywords for domain whois labels

#### 1.2.0 - 12 Feb 2019
- Added - Support for IDN with Punycode
