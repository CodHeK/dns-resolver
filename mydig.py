#!/usr/bin/env python

import sys, time
from utils.print import output

from dns_resolvers import DNSResolverFactory
from dnssec_resolvers import DNSSECResolverFactory
from constants import DNSSEC_STATUS_CODES


if __name__ == '__main__':
    try:
        args = sys.argv[1:]

        if len(args) == 2:
            # DNS Mode
            domain_name, dns_query_type = args

            query_start = time.time()
            start_time = time.ctime(query_start)

            # Choose a resolver based on the dns query
            resolver = DNSResolverFactory.get_resolver(domain_name, dns_query_type)
            response = resolver.resolve()

            query_end = time.time()
            query_time = int((query_end - query_start) * 1000)

            # Print output to terminal
            output(
                domain_name=domain_name,
                dns_query_type=dns_query_type,
                response=response,
                query_time=query_time,
                start_time=start_time
            )
        elif len(args) == 3:
            # DNSSec Mode
            domain_name, dns_query_type, dnssec = args
            
            if dnssec == '--dnssec':
                query_start = time.time()
                start_time = time.ctime(query_start)

                # Choose a resolver based on the dns query
                resolver = DNSSECResolverFactory.get_resolver(domain_name, dns_query_type)
                status, response = resolver.resolve()

                query_end = time.time()
                query_time = int((query_end - query_start) * 1000)

                if status == DNSSEC_STATUS_CODES.SUPPORTED:
                    # Print output to terminal
                    output(
                        domain_name=domain_name,
                        dns_query_type=dns_query_type,
                        response=response,
                        query_time=query_time,
                        start_time=start_time
                    )
                elif status == DNSSEC_STATUS_CODES.NOT_SUPPORTED:
                    print("DNSSec not supported")
                elif status == DNSSEC_STATUS_CODES.VERIFICATION_FAILED:
                    print("DNSSec verification failed")

        else:
            raise Exception('Two mandatory arguments required: <Domain name> <DNS Query Type> AND --dnssec flag for a DNSSec resolution')
    except Exception as e:
        print(e)

