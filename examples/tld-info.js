const whoiser = require('../index.js');

(async () => {

	let tldInfo = await whoiser('blog')

	console.log('TLD Organisation:', tldInfo.organisation)
	console.log('TLD creation date:', tldInfo.created)
	console.log('TLD WHOIS server:', tldInfo.whois)

})();

/* Full WHOIS info for .blog TLD as of April 2021
{
  domain: 'BLOG',
  organisation: {
    organisation: 'Knock Knock WHOIS There, LLC',
    address: '60 29th Street\nSAN FRANCISCO\nCA 94110\nUnited States'
  },
  contacts: {
    administrative: {
      contact: 'administrative',
      name: 'Head of Business Development',
      organisation: 'Knock Knock WhoIS There, LLC (KKWT)',
      address: '60 29th St.\nSan Francisco\nCA 94110\nUnited States',
      phone: '+1.8772733049',
      'e-mail': 'welcome@my.blog'
    },
    technical: {
      contact: 'technical',
      name: 'CTO',
      organisation: 'CentralNic',
      address: '4th Floor, Saddlers House\n' +
        '44 Gutter Lane\n' +
        'London\n' +
        'EC2V 6BR\n' +
        'United Kingdom',
      phone: '+44.2033880600',
      'e-mail': 'tld.ops@centralnic.com'
    }
  },
  nserver: 'A.NIC.BLOG 194.169.218.94 2001:67c:13cc:0:0:0:1:94\n' +
    'B.NIC.BLOG 185.24.64.94 2a04:2b00:13cc:0:0:0:1:94\n' +
    'C.NIC.BLOG 212.18.248.94 2a04:2b00:13ee:0:0:0:0:94\n' +
    'D.NIC.BLOG 212.18.249.94 2a04:2b00:13ff:0:0:0:0:94',
  'ds-rdata': '43975 8 2 94023BE3A769704F45ECB9FEA13BBBAB6ADCDB4D8BB39E621E3CBF223FB5CA53\n' +
    '16976 8 1 f4535c694f892ffeb740c35cc9665b52e360df7d\n' +
    '16976 8 2 9862de44e1e7e44215165000c4b87bd3f46d439c686166da0ca79e06896958b7',
  whois: 'whois.nic.blog',
  status: 'ACTIVE',
  remarks: 'Registration information: http://nic.blog',
  created: '2016-05-12',
  changed: '2020-04-15',
  source: 'IANA',
  text: [
    '% IANA WHOIS server',
    '% for more information on IANA, visit http://www.iana.org',
    '% This query returned 1 object'
  ]
}
*/
