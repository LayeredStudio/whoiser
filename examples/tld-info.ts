import { whoisTld } from '../src/whoiser.ts'

const tldInfo = await whoisTld('blog')

console.log('TLD Organisation:', tldInfo.organisation)
console.log('TLD creation date:', tldInfo.created)
console.log('TLD WHOIS server:', tldInfo.whois)
