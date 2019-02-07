const whoiser = require('./index.js');

(async () => {

	// whoiser fn auto discovers whois servers for domains, tld or IPs
	let tldInfo = await whoiser('blog')
	let domainInfo = await whoiser('google.com')
	let ipInfo = await whoiser('1.1.1.1')

	// OR use specific functions
	let domainInfo2 = await whoiser.domain('cloudflare.com', {host: 'whois.cloudflare.com'})

	console.log(tldInfo, domainInfo, ipInfo, domainInfo2)
})();
