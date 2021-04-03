const whoiser = require('../index.js');

(async () => {
	const domainName = 'google.com'


	// retrieve detailed WHOIS info from Registrar & Registry WHOIS servers
	const domainInfo = await whoiser(domainName)

	const foundWhoisServers = Object.keys(domainInfo)

	console.log(`Queried ${foundWhoisServers.length} WHOIS servers (${foundWhoisServers.join(', ')}) for WHOIS info`)
	console.log(domainInfo)

})();
