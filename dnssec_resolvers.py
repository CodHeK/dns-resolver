from abc import abstractmethod
import dns.query
import dns.resolver
import dns.message
from dns.dnssec import ValidationFailure
import sys, time

from custom_resolver import CustomResolver
from dns_resolvers import DNSResolverFactory
from constants import DNSSEC_STATUS_CODES, RDATATYPE_MAP


class A_Resolver(CustomResolver):
    def __init__(self, domain_name, dnssec):
        super().__init__(domain_name, dnssec)
        self.query_type = dns.rdatatype.A
    
    def resolve(self):
        try:
            _, _, server_ipv4 = self.get_root_ns_info()

            parent_zone_query_response = self.query(self.domain_name, self.query_type, server_ipv4)
            parent_zone_dnskey_response = self.query('.', dns.rdatatype.DNSKEY, server_ipv4)

            # Validate the RRSIG for the DNSKEY records
            query_name, dnskey_rrset = self.verify_dnskey(parent_zone_dnskey_response)

            if(
                # Validate the RRSIG for the DS records
                self.verify_rdtype(
                    parent_zone_query_response,
                    rdtype=dns.rdatatype.DS,
                    keys={ query_name: dnskey_rrset }
                )
                and
                # Verify the root zone with hardcoded root KSK
                self.verify_zone(parent_zone_dnskey_response, None)
            ):  
                # Keep looping until STATUS is not None
                STATUS = None
                while True:
                    if len(parent_zone_query_response.additional) > 0:
                        next_query = parent_zone_query_response.authority[0].name.to_text()
                        for rrset in parent_zone_query_response.additional:
                            server_ipv4 = rrset[0].to_text()

                            child_zone_query_response = self.query(self.domain_name, self.query_type, server_ipv4)
                            child_zone_dnskey_response = self.query(next_query, dns.rdatatype.DNSKEY, server_ipv4)

                            if len(child_zone_query_response.answer) > 0:
                                # Reached the authoritative name server
                                STATUS = DNSSEC_STATUS_CODES.SUPPORTED
                                break
                            if not self.check_ds_entry_exists(child_zone_query_response):
                                # No DS Record found in the response (has NSEC/NSEC3 instead), hence DNSSEC is not Supported
                                STATUS = DNSSEC_STATUS_CODES.NOT_SUPPORTED
                                break
                            
                            # Establish trust for the DNSKEY Records
                            query_name, dnskey_rrset = self.verify_dnskey(child_zone_dnskey_response)

                            if(
                                # Establish trust for the DS Records
                                self.verify_rdtype(
                                    child_zone_query_response, 
                                    rdtype=dns.rdatatype.DS,
                                    keys={ query_name: dnskey_rrset }
                                )
                                and 
                                # Verify zone using child public KSK and parent DS record 
                                self.verify_zone(child_zone_dnskey_response, parent_zone_query_response)
                            ):
                                parent_zone_query_response = child_zone_query_response
                                parent_zone_dnskey_response = child_zone_dnskey_response
                                break

                    else:
                        # Additional section is empty, resolve IP for nameserver
                        rrset = parent_zone_query_response.authority[0]
                        rr = rrset[0]

                        resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'A')
                        response = resolver.resolve()

                        server_ipv4 = response[0][0]

                        # Add the resolved nameserver IP into the additional section
                        # for further iterations
                        parent_zone_query_response.additional.append(
                            dns.rrset.from_text(rr.to_text(), 172800, 'IN', 'A', server_ipv4)
                        )

                    if STATUS == DNSSEC_STATUS_CODES.NOT_SUPPORTED:
                        return STATUS, []
                    elif STATUS == DNSSEC_STATUS_CODES.SUPPORTED:
                        try:
                            rrset = child_zone_query_response.answer[0]
                            rr = rrset[0]

                            if rr.rdtype == self.query_type:
                                # Establish trust for the DNSKEY Records
                                query_name, dnskey_rrset = self.verify_dnskey(child_zone_dnskey_response)
                                
                                if(
                                    # Establish trust for the query type Records
                                    self.verify_rdtype(
                                        child_zone_query_response, 
                                        rdtype=self.query_type,
                                        keys={ query_name: dnskey_rrset }
                                    )
                                    and
                                    # Verify zone using child public KSK and parent DS record 
                                    self.verify_zone(child_zone_dnskey_response, parent_zone_query_response)
                                ):

                                    answers = [ 
                                        (res.to_text(), RDATATYPE_MAP[res.rdtype], rrset.name) for res in rrset
                                    ]

                                    return STATUS, answers
                            elif rr.rdtype == dns.rdatatype.CNAME:
                                resolver = DNSSECResolverFactory.get_resolver(rr.to_text(), self.query_type)
                                return resolver.resolve()

                        except Exception as e:
                            return DNSSEC_STATUS_CODES.VERIFICATION_FAILED, []

        except Exception as e:
            print("[DNSSEC] A_Resolver returned an error ", e)

        except ValidationFailure:
            return DNSSEC_STATUS_CODES.VERIFICATION_FAILED, []


class NS_Resolver(CustomResolver):
    def __init__(self, domain_name, dnssec):
        super().__init__(domain_name, dnssec)
        self.query_type = dns.rdatatype.NS

    def resolve(self):
        try:
            _, _, server_ipv4 = self.get_root_ns_info()

            parent_zone_query_response = self.query(self.domain_name, self.query_type, server_ipv4)
            parent_zone_dnskey_response = self.query('.', dns.rdatatype.DNSKEY, server_ipv4)

            # Validate the RRSIG for the DNSKEY records
            query_name, dnskey_rrset = self.verify_dnskey(parent_zone_dnskey_response)
            
            # Establish chain of trust
            if(
                # Validate the RRSIG for the DS records
                self.verify_rdtype(
                    parent_zone_query_response,
                    rdtype=dns.rdatatype.DS,
                    keys={ query_name: dnskey_rrset }
                )
                and
                # Verify the root zone with hardcoded root KSK
                self.verify_zone(parent_zone_dnskey_response, None)
            ):
                # Keep looping until STATUS is not None
                STATUS = None
                while True:
                    if len(parent_zone_query_response.additional) > 0:
                        next_query = parent_zone_query_response.authority[0].name.to_text()
                        for rrset in parent_zone_query_response.additional:
                            server_ipv4 = rrset[0].to_text()

                            child_zone_query_response = self.query(self.domain_name, self.query_type, server_ipv4)
                            child_zone_dnskey_response = self.query(next_query, dns.rdatatype.DNSKEY, server_ipv4)

                            if len(child_zone_query_response.answer) > 0:
                                # Reached the authoritative name server
                                STATUS = DNSSEC_STATUS_CODES.SUPPORTED
                                break
                            if not self.check_ds_entry_exists(child_zone_query_response):
                                # No DS Record found in the response (has NSEC/NSEC3 instead), hence DNSSEC is not Supported
                                STATUS = DNSSEC_STATUS_CODES.NOT_SUPPORTED
                                break
                            
                            # Establish trust for the DNSKEY Records
                            query_name, dnskey_rrset = self.verify_dnskey(child_zone_dnskey_response)

                            # Establish chain of trust
                            if(
                                # Establish trust for the DS Records
                                self.verify_rdtype(
                                    child_zone_query_response, 
                                    rdtype=dns.rdatatype.DS,
                                    keys={ query_name: dnskey_rrset }
                                )
                                and
                                # Verify zone using child public KSK and parent DS record 
                                self.verify_zone(child_zone_dnskey_response, parent_zone_query_response)
                            ):
                                parent_zone_query_response = child_zone_query_response
                                parent_zone_dnskey_response = child_zone_dnskey_response
                                break

                    else:
                        # Additional section is empty, resolve IP for nameserver
                        rrset = parent_zone_query_response.authority[0]
                        rr = rrset[0]

                        resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'A')
                        response = resolver.resolve()

                        server_ipv4 = response[0][0]

                        # Add the resolved nameserver IP into the additional section
                        # for further iterations
                        parent_zone_query_response.additional.append(
                            dns.rrset.from_text(rr.to_text(), 172800, 'IN', 'A', server_ipv4)
                        )

                    if STATUS == DNSSEC_STATUS_CODES.NOT_SUPPORTED:
                        return STATUS, []
                    elif STATUS == DNSSEC_STATUS_CODES.SUPPORTED:
                        try:
                            # Establish trust for the DNSKEY Records
                            query_name, dnskey_rrset = self.verify_dnskey(child_zone_dnskey_response)

                            if(
                                # Establish trust for the query type Records
                                self.verify_rdtype(
                                    child_zone_query_response, 
                                    rdtype=self.query_type,
                                    keys={ query_name: dnskey_rrset }
                                )
                                and
                                # Verify zone using child public KSK and parent DS record 
                                self.verify_zone(child_zone_dnskey_response, parent_zone_query_response)
                            ):
                                rrset = child_zone_query_response.answer[0]
                                answers = [ (res.to_text(), RDATATYPE_MAP[res.rdtype], rrset.name) for res in rrset ]

                                return STATUS, answers
                                
                        except Exception as e:
                            return DNSSEC_STATUS_CODES.VERIFICATION_FAILED, []

        except Exception as e:
            print("[DNSSEC] NS_Resolver returned an error ", e)
        
        except ValidationFailure:
            return DNSSEC_STATUS_CODES.VERIFICATION_FAILED, []


class MX_Resolver(CustomResolver):
    def __init__(self, domain_name, dnssec):
        super().__init__(domain_name, dnssec)
        self.query_type = dns.rdatatype.MX

    def resolve(self):
        try:
            _, _, server_ipv4 = self.get_root_ns_info()

            parent_zone_query_response = self.query(self.domain_name, self.query_type, server_ipv4)
            parent_zone_dnskey_response = self.query('.', dns.rdatatype.DNSKEY, server_ipv4)

            # Validate the RRSIG for the DNSKEY records
            query_name, dnskey_rrset = self.verify_dnskey(parent_zone_dnskey_response)

            if(
                # Validate the RRSIG for the DS records
                self.verify_rdtype(
                    parent_zone_query_response,
                    rdtype=dns.rdatatype.DS,
                    keys={ query_name: dnskey_rrset }
                )
                and
                # Verify the root zone with hardcoded root KSK
                self.verify_zone(parent_zone_dnskey_response, None)
            ):
                # Keep looping until STATUS is not None
                STATUS = None
                while True:
                    if len(parent_zone_query_response.additional) > 0:
                        next_query = parent_zone_query_response.authority[0].name.to_text()
                        for rrset in parent_zone_query_response.additional:
                            server_ipv4 = rrset[0].to_text()

                            child_zone_query_response = self.query(self.domain_name, self.query_type, server_ipv4)
                            child_zone_dnskey_response = self.query(next_query, dns.rdatatype.DNSKEY, server_ipv4)

                            if len(child_zone_query_response.answer) > 0:
                                # Reached the authoritative name server
                                STATUS = DNSSEC_STATUS_CODES.SUPPORTED
                                break
                            if not self.check_ds_entry_exists(child_zone_query_response):
                                # No DS Record found in the response (has NSEC/NSEC3 instead), hence DNSSEC is not Supported
                                STATUS = DNSSEC_STATUS_CODES.NOT_SUPPORTED
                                break
                            
                            # Establish trust for the DNSKEY Records
                            query_name, dnskey_rrset = self.verify_dnskey(child_zone_dnskey_response)

                            if(
                                # Establish trust for the DS Records
                                self.verify_rdtype(
                                    child_zone_query_response, 
                                    rdtype=dns.rdatatype.DS,
                                    keys={ query_name: dnskey_rrset }
                                )
                                and
                                # Verify zone using child public KSK and parent DS record 
                                self.verify_zone(child_zone_dnskey_response, parent_zone_query_response)
                            ):
                                parent_zone_query_response = child_zone_query_response
                                parent_zone_dnskey_response = child_zone_dnskey_response
                                break

                    else:
                        # Additional section is empty, resolve IP for nameserver
                        rrset = parent_zone_query_response.authority[0]
                        rr = rrset[0]

                        resolver = DNSResolverFactory.get_resolver(rr.to_text(), 'A')
                        response = resolver.resolve()

                        server_ipv4 = response[0][0]

                        # Add the resolved nameserver IP into the additional section
                        # for further iterations
                        parent_zone_query_response.additional.append(
                            dns.rrset.from_text(rr.to_text(), 172800, 'IN', 'A', server_ipv4)
                        )

                    if STATUS == DNSSEC_STATUS_CODES.NOT_SUPPORTED:
                        return STATUS, []
                    elif STATUS == DNSSEC_STATUS_CODES.SUPPORTED:
                        try:
                            rrset = child_zone_query_response.answer[0]
                            rr = rrset[0]

                            if rr.rdtype == self.query_type:
                                # Establish trust for the DNSKEY Records
                                query_name, dnskey_rrset = self.verify_dnskey(child_zone_dnskey_response)
                                
                                if(
                                    # Establish trust for the query type Records
                                    self.verify_rdtype(
                                        child_zone_query_response, 
                                        rdtype=self.query_type,
                                        keys={ query_name: dnskey_rrset }
                                    )
                                    and
                                    # Verify zone using child public KSK and parent DS record 
                                    self.verify_zone(child_zone_dnskey_response, parent_zone_query_response)
                                ):
                                    answers = [ 
                                        (res.to_text(), RDATATYPE_MAP[res.rdtype], rrset.name) for res in rrset
                                    ]

                                    return STATUS, answers
                            elif rr.rdtype == dns.rdatatype.CNAME:
                                resolver = DNSSECResolverFactory.get_resolver(rr.to_text(), self.query_type)
                                return resolver.resolve()

                        except Exception as e:
                            return DNSSEC_STATUS_CODES.VERIFICATION_FAILED, []

        except Exception as e:
            print("[DNSSEC] MX_Resolver returned an error ", e)
        
        except ValidationFailure:
            return DNSSEC_STATUS_CODES.VERIFICATION_FAILED, []


class DNSSECResolverFactory:
    __dnssec = True
    __choice = {
        'A': A_Resolver,
        'NS': NS_Resolver,
        'MX': MX_Resolver
    }
    
    @staticmethod
    def get_resolver(domain_name, query_type):
        return DNSSECResolverFactory.__choice[query_type](domain_name, DNSSECResolverFactory.__dnssec)