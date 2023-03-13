

export async function get(url: string) {
    try {
        let response = await fetch(url)
        return response.json()
    } catch {
        return
    }
}


export async function post(url: string, data?: any) {
    try {
        let options: RequestInit = {
            method: 'POST',
            cache: 'no-cache',
            headers: {
                'Content-Type': 'application/json',
            },
        }
        if (data) {
            options.body = JSON.stringify(data)
        }
        let response = await fetch(url, options)
        return await response.json()
    } catch {
        return
    }
}

// from dnslib.QTYPE
export const QTYPE = Object.values({
    1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 10:'NULL', 12:'PTR', 13:'HINFO',
    15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
    28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
    37:'CERT', 38:'A6', 39:'DNAME', 41:'OPT', 42:'APL',
    43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
    48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
    52:'TLSA', 53:'HIP', 55:'HIP', 59:'CDS', 60:'CDNSKEY',
    61:'OPENPGPKEY', 62:'CSYNC', 63:'ZONEMD', 64:'SVCB',
    65:'HTTPS', 99:'SPF', 108:'EUI48', 109:'EUI64', 249:'TKEY',
    250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 256:'URI',
    257:'CAA', 32768:'TA', 32769:'DLV'
})
