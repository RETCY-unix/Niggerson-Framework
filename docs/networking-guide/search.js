// Search functionality for Networking Field Manual
// Client-side search index

const searchIndex = [
    // Module 1
    {
        title: "Networking Fundamentals", url: "module-1/networking-fundamentals.html",
        keywords: "networking network definition LAN WAN MAN PAN topology star bus ring mesh client server peer"
    },
    {
        title: "IP Addressing", url: "module-1/ip-addressing.html",
        keywords: "IP IPv4 IPv6 address subnet mask CIDR class A B C private public DHCP static dynamic"
    },
    {
        title: "ISP Internet Service Providers", url: "module-1/isp.html",
        keywords: "ISP tier peering transit BGP AS autonomous system IXP DSL fiber cable"
    },
    {
        title: "TCP/IP Protocol", url: "module-1/tcp-ip.html",
        keywords: "TCP UDP port socket handshake SYN ACK FIN RST three-way segment datagram"
    },
    {
        title: "DNS Domain Name System", url: "module-1/dns.html",
        keywords: "DNS domain name resolution A AAAA CNAME MX NS PTR TXT record resolver authoritative"
    },
    {
        title: "OSI Model", url: "module-1/osi-model.html",
        keywords: "OSI layer physical data link network transport session presentation application encapsulation"
    },
    {
        title: "MAC Addresses", url: "module-1/mac-addresses.html",
        keywords: "MAC address ARP Ethernet frame OUI switch CAM table broadcast"
    },
    {
        title: "Subnetting", url: "module-1/subnetting.html",
        keywords: "subnet subnetting VLSM supernetting CIDR network host broadcast mask"
    },

    // Module 2
    {
        title: "Port Scanning Techniques", url: "module-2/port-scanning.html",
        keywords: "port scan SYN FIN XMAS NULL ACK stealth nmap reconnaissance fingerprint"
    },
    {
        title: "ARP Attacks", url: "module-2/arp-attacks.html",
        keywords: "ARP spoofing poisoning cache MAC flooding gratuitous MITM"
    },
    {
        title: "Layer 2 Attacks", url: "module-2/layer2-attacks.html",
        keywords: "VLAN hopping STP spanning tree DHCP starvation rogue MAC spoofing CDP LLDP"
    },
    {
        title: "MITM Man-in-the-Middle", url: "module-2/mitm-attacks.html",
        keywords: "MITM man middle SSL stripping HSTS session hijacking cookie interception"
    },
    {
        title: "MOTS Evil Twin", url: "module-2/mots-evil-twin.html",
        keywords: "MOTS man side QUANTUM evil twin karma deauth wireless rogue AP"
    },
    {
        title: "DNS Attacks", url: "module-2/dns-attacks.html",
        keywords: "DNS cache poisoning Kaminsky spoofing hijacking tunneling rebinding"
    },
    {
        title: "Tunneling Covert Channels", url: "module-2/tunneling-attacks.html",
        keywords: "tunnel ICMP HTTP SSH pivot covert channel exfiltration C2"
    },

    // Module 3
    {
        title: "Port Scanner C Implementation", url: "module-3/index.html",
        keywords: "C code scanner implementation connect SYN stealth raw socket TCP handshake programming"
    }
];

function performSearch(query) {
    if (!query || query.length < 2) return [];

    const terms = query.toLowerCase().split(/\s+/);
    const results = [];

    searchIndex.forEach(item => {
        const searchText = (item.title + " " + item.keywords).toLowerCase();
        let score = 0;

        terms.forEach(term => {
            if (searchText.includes(term)) {
                score++;
                if (item.title.toLowerCase().includes(term)) score += 2;
            }
        });

        if (score > 0) {
            results.push({ ...item, score });
        }
    });

    return results.sort((a, b) => b.score - a.score);
}

function initSearch() {
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');

    if (!searchInput || !searchResults) return;

    searchInput.addEventListener('input', function () {
        const query = this.value.trim();
        const results = performSearch(query);

        if (query.length < 2) {
            searchResults.style.display = 'none';
            return;
        }

        if (results.length === 0) {
            searchResults.innerHTML = '<div class="search-no-results">No results found</div>';
        } else {
            searchResults.innerHTML = results.map(r =>
                `<a href="${r.url}" class="search-result-item">
                    <div class="search-result-title">${r.title}</div>
                </a>`
            ).join('');
        }
        searchResults.style.display = 'block';
    });

    // Close on click outside
    document.addEventListener('click', function (e) {
        if (!e.target.closest('.search-container')) {
            searchResults.style.display = 'none';
        }
    });

    // Close on Escape
    searchInput.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            searchResults.style.display = 'none';
            this.blur();
        }
    });
}

document.addEventListener('DOMContentLoaded', initSearch);
