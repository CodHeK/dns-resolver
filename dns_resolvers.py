'''
Assignment Part - A
'''
from abc import abstractmethod
import dns.query
import dns.resolver
import dns.message
import sys, time

from custom_resolver import CustomResolver
from constants import RDATATYPE_MAP

class A_Resolver(CustomResolver):
    def __init__(self, domain_name, dnssec):
        super().__init__(domain_name, dnssec)
        self.query_type = dns.rdatatype.A
        self.cache = {}
    
    def resolve(self):
        domain = dns.name.from_text(self.domain_name)

        response, _, server_ipv4 = self.get_root_ns_info()

        depth = 2
        query_left = False

        while not query_left:
            s = domain.split(depth)
            
            '''
                Iteratively break the domain into two parts
                Eg: (for depth = 2)
                    google.com.
                    query_left = <google>
                    curr_query = <com.>
            '''
            query_left = s[0].to_text() == "@"
            curr_query = s[1].to_text()

            response = self.query(curr_query, self.query_type, server_ipv4)
            rcode = response.rcode()

            if rcode == dns.rcode.NOERROR:
                if query_left:
                    # Reached the end of the query, check if answer section is not empty
                    if len(response.answer) > 0:
                        rrset = response.answer[0]
                        rr = rrset[0]

                        if rr.rdtype == self.query_type:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                        elif rr.rdtype == dns.rdatatype.CNAME:
                            # Get the A record for this CNAME
                            resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'A')
                            return resolver.resolve()
                
                # Get the nameserver IP from the additional section 
                if len(response.additional) > 0 and len(response.authority) > 0:
                    # Cache Nameservers to prevent cyclic lookups
                    for res in response.authority[0]:
                        self.cache[res.to_text()] = True

                    for res in response.additional:
                        rr = res[0]
                        if rr.rdtype == dns.rdatatype.A:
                            # A record for this nameserver
                            server_ipv4 = rr.to_text()
                            break
                        
                    if query_left:
                        # Keep iterating till we get an A record
                        query_left = False
                        continue
                else:
                    # Additional section is empty, resolve IP for nameserver
                    if len(response.authority) > 0:
                        rrset = response.authority[0]
                    else:
                        rrset = response.answer[0]
                    
                    rr = rrset[0]

                    if rr.rdtype == dns.rdatatype.NS:
                        # Don't resolve the nameserver if already in cache (used to prevent cycles)
                        if rr.to_text() not in self.cache:
                            resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'A')
                            response = resolver.resolve()

                            server_ipv4 = response[0][0]
                        
                        # Keep iterating till answer section is non-empty
                        if query_left:
                            query_left = False
                            continue

                depth += 1


class NS_Resolver(CustomResolver):
    def __init__(self, domain_name, dnssec):
        super().__init__(domain_name, dnssec)
        self.query_type = dns.rdatatype.NS

    def resolve(self):
        domain = dns.name.from_text(self.domain_name)

        if self.domain_name == '.':
            root_servers = self.get_root_server_hints()
            return [ name for name, ipv4 in root_servers.items()]

        response, _, server_ipv4 = self.get_root_ns_info()

        depth = 2
        query_left = False

        while not query_left:
            s = domain.split(depth)

            '''
                Iteratively break the domain into two parts
                Eg: (for depth = 2)
                    google.com.
                    query_left = <google>
                    curr_query = <com.>
            '''
            query_left = s[0].to_text() == "@"
            curr_query = s[1]
            
            response = self.query(curr_query, self.query_type, server_ipv4)
            rcode = response.rcode()

            if rcode == dns.rcode.NOERROR:
                if query_left:
                    # Reached the end of the query, check if answer section is not empty
                    if len(response.answer) > 0:
                        rrset = response.answer[0]
                        rr = rrset[0]

                        if rr.rdtype == self.query_type:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                        elif rr.rdtype == dns.rdatatype.CNAME:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                    
                    # Handle cases when answer is returned in the authority section
                    elif len(response.authority) > 0:
                        rrset = response.authority[0]
                        rr = rrset[0]

                        if rr.rdtype == self.query_type:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                        elif rr.rdtype == dns.rdatatype.SOA:
                            raise Exception('SOA records found for ' + str(self.domain_name))
            
                # Get the nameserver IP from the additional section              
                if len(response.additional) > 0:
                    for res in response.additional:
                        rr = res[0]
                        if rr.rdtype == dns.rdatatype.A:
                            # A record for this nameserver
                            server_ipv4 = rr.to_text()
                            break
                    
                    # Keep iterating till answer section is non-empty
                    if query_left:
                        query_left = False
                        continue

                depth += 1 


class MX_Resolver(CustomResolver):
    def __init__(self, domain_name, dnssec):
        super().__init__(domain_name, dnssec)
        self.query_type = dns.rdatatype.MX

    def resolve(self):
        domain = dns.name.from_text(self.domain_name)

        response, _, server_ipv4 = self.get_root_ns_info()

        depth = 2
        query_left = False

        while not query_left:
            s = domain.split(depth)

            '''
                Iteratively break the domain into two parts
                Eg: (for depth = 2)
                    google.com.
                    query_left = <google>
                    curr_query = <com.>
            '''
            query_left = s[0].to_text() == "@"
            curr_query = s[1]

            response = self.query(curr_query, self.query_type, server_ipv4)

            rcode = response.rcode()
            if rcode == dns.rcode.NOERROR:
                if query_left:
                    # Reached the end of the query, check if answer section is not empty
                    if len(response.answer) > 0:
                        rrset = response.answer[0]
                        rr = rrset[0]

                        if rr.rdtype == self.query_type:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                        elif rr.rdtype == dns.rdatatype.CNAME:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                    
                    elif len(response.authority) > 0:
                        rrset = response.authority[0]
                        rr = rrset[0]

                        if rr.rdtype == self.query_type:
                            return [ (res.to_text(), RDATATYPE_MAP[rr.rdtype], rrset.name) for res in rrset ]
                        elif rr.rdtype == dns.rdatatype.NS:
                            resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'A')
                            res = resolver.resolve()

                            server_ipv4 = res[0][0]

                            query_left = False
                            continue

                        elif rr.rdtype == dns.rdatatype.CNAME:
                            # Get the MX record for this CNAME
                            resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'MX')
                            return resolver.resolve()
                        
                        elif rr.rdtype == dns.rdatatype.SOA:
                            raise Exception('SOA records found for ' + str(self.domain_name))
                                       
                if len(response.additional) > 0:
                    for res in response.additional:
                        rr =  res[0]
                        if rr.rdtype == dns.rdatatype.A:
                            # A record for this nameserver
                            server_ipv4 = rr.to_text()
                            break
                    
                    # Keep iterating till answer section is non-empty
                    if query_left:
                        query_left = False
                        continue

                depth += 1    


class DNSResolverFactory:
    __dnssec = False
    __choice = {
        'A': A_Resolver,
        'NS': NS_Resolver,
        'MX': MX_Resolver
    }
    
    @staticmethod
    def get_resolver(domain_name, query_type):
        return DNSResolverFactory.__choice[query_type](domain_name, DNSResolverFactory.__dnssec)