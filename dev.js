const whoiser = require('./index.js');

(async () => {

	// WHOIS info from Registry (Verisign) AND Registrar (MarkMonitor) whois servers
	let domainInfo = await whoiser('google.com')

	// OR with options for whois server and how many WHOIS servers to query
	let domainInfo2 = await whoiser.domain('blog.google', {host: 'whois.nic.google', follow: 1})

	console.log(domainInfo, domainInfo2)
})();