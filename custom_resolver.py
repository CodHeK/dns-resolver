from abc import abstractmethod
import dns.query
import dns.resolver
import dns.message
import dns.dnssec

class CustomResolver:
    def __init__(self, domain_name, dnssec):
        self.domain_name = domain_name
        self.dnssec = dnssec
        self.ROOT_HINTS_FILE = 'root_hints.txt' # Has the 13 IPv4 addresses of the root servers
        self.algorithms = {
            '1': 'SHA1',
            '2': 'SHA256',
            '3': 'SHA1',
            '4': 'SHA1',
            '5': 'SHA1',
            '6': 'SHA1',
            '7': 'SHA1',
            '8': 'SHA1',
            '10': 'SHA1',
        }
        # From: http://data.iana.org/root-anchors/root-anchors.xml
        self.root_anchors = [
            dns.rrset.from_text('.', 86400, 'IN', 'DS', '19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5'),
            dns.rrset.from_text('.', 86400, 'IN', 'DS', '20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D')
        ]


    def query(self, q, query_type, server_ipv4):
        query = dns.message.make_query(q, query_type, want_dnssec=self.dnssec)
        response = dns.query.udp(query, timeout=2.0, where=server_ipv4)

        return response


    def retrieve_rrset_info(self, response, rdtype):
        required_rrset, rrsig, query_name = '', '', ''
        records = []

        if rdtype in [ dns.rdatatype.DNSKEY, dns.rdatatype.A, dns.rdatatype.MX ]:
            records = response.answer
        elif rdtype in [ dns.rdatatype.DS, dns.rdatatype.NS ]:
            if len(response.authority) > 0:
                records = response.authority
            else:
                records = response.answer

        for rrset in records:
            if rrset.rdtype == rdtype:
                required_rrset = rrset
                query_name = rrset.name
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig = rrset

        return required_rrset, rrsig, query_name


    def verify_dnskey(self, response, **kwargs):
        '''
            Verify the DNSKEY record rrset against the DNSKEY record RRSIG
        '''
        try:
            dnskey_rrset, dnskey_rrsig, query_name = self.retrieve_rrset_info(response, dns.rdatatype.DNSKEY)

            # Verifying the complete RRset, instead of just the first one 
            # as full RRset that gets digitally signed
            dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, { query_name: dnskey_rrset })
            # print(query_name, ' DNSKEY verified')

            return query_name, dnskey_rrset
        except Exception as e:
            print('Could not verify DNSKEY record for ', query_name)
            raise e
    
    def verify_rdtype(self, response, rdtype, **kwargs):
        '''
            Verify any rdtype record rrset against its RRSIG record
        '''
        try:
            rdtype_record, rdtype_rrsig, query_name = self.retrieve_rrset_info(response, rdtype)
            dns.dnssec.validate(rdtype_record, rdtype_rrsig, **kwargs)            
            # print(query_name, ' ', rdtype, '  verified')

            return True
        except Exception as e:
            print('Could not verify ', rdtype, ' for ', query_name)
            raise e
    

    def get_parent_ds_record(self, response):
        '''
            Get the DS record from the given response
        '''
        ds_record, ds_rrsig, query_name = self.retrieve_rrset_info(response, dns.rdatatype.DS)
        return ds_record, query_name
    

    def validate_hash(self, query_name, child_public_ksk, parent_ds_record):
        parent_hashed_public_ksk = parent_ds_record[0]

        # Hash the child zone public KSK
        child_hashed_public_ksk = dns.dnssec.make_ds(
            query_name, 
            child_public_ksk, 
            self.algorithms[str(parent_hashed_public_ksk.digest_type)]
        )

        if child_hashed_public_ksk != parent_hashed_public_ksk:
            return False
        
        return True

    
    def verify_zone(self, response, response_parent):
        '''
            Verifying if the hashed child zone public KSK 
            matches the DS record from parent zone
        '''
        try:
            dnskey_record, dnskey_rrsig, query_name = self.retrieve_rrset_info(response, dns.rdatatype.DNSKEY)
            child_public_ksk = None
            for dnskey in dnskey_record:
                if dnskey.flags == 257:
                    child_public_ksk = dnskey
                    break
            if child_public_ksk:   
                if response_parent:
                    parent_ds_record, query_name = self.get_parent_ds_record(response_parent)

                    if not self.validate_hash(query_name, child_public_ksk, parent_ds_record):
                        raise Exception("Hashes don't match")
                else:
                    # Verify directly with harcoded root anchors for the root
                    for root_anchor in self.root_anchors:
                        if self.validate_hash('.', child_public_ksk, root_anchor):
                            return True
                    raise Exception("Hashes don't match")
                
                return True
            return Exception("Couldn't find 'child_public_ksk' in the dnskey response")

        except Exception as e:
            print('Could not verify zone for ', query_name, ' Reason: ', e)
            raise e

    
    def check_ds_entry_exists(self, response):
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.DS:
                return True
        return False
    

    def get_root_server_hints(self):
        root_server_hints = {}
        f = open(self.ROOT_HINTS_FILE, 'r')
        for line in f.readlines():
            root_server_name, root_server_ipv4 = line.strip().split(' ')
            root_server_hints[root_server_name] = root_server_ipv4
        
        return root_server_hints

    
    def get_root_ns_info(self):
        root_servers = self.get_root_server_hints()

        server_ipv4 = ''
        root_ns = ''
        for name, ipv4 in root_servers.items():
            response = self.query('.', dns.rdatatype.NS, ipv4)

            if len(response.additional) > 0:
                root_ns, server_ipv4 = name, ipv4
                break
            else:
                print("Root server ", name, " does not have TLD information, checking next root server...")
        
        return response, root_ns, server_ipv4
    
    @abstractmethod
    def resolve(self):
        '''
            Implement your custom resolve method based on the DNS query
        '''
        pass