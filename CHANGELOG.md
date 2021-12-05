# Whoiser change log

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
