import sys
import dns.resolver

from mydig import DNSResolverFactory 
from utils.print import output

import time

WEBSITES_LIST_FILE = 'top_25_websites.txt'
OUTPUT_DIR = 'logs'

def read_websites_from_file():
    websites = []
    f = open(WEBSITES_LIST_FILE, 'r')
    for domain in f.readlines():
        websites.append(domain.strip().lower())
    
    return websites


if __name__ == '__main__':
    try:
        args = sys.argv[1:]

        websites = read_websites_from_file()
        dns_query_type = 'A'
        iterations = 10

        if len(args) == 0:
            # Use my own DNS Resolver
            resolver_stats = {}

            for domain in websites:
                total_time = 0.0
                for i in range(iterations):
                    start_ts = time.time()

                    resolver = DNSResolverFactory.get_resolver(domain, dns_query_type)
                    response = resolver.resolve()

                    end_ts = time.time()

                    total_time += int((end_ts - start_ts) * 1000) # msec

                    file_path = OUTPUT_DIR + '/' + domain.split('.')[0] + '.txt'

                    output(
                        domain_name=domain,
                        dns_query_type=dns_query_type,
                        response=response,
                        query_time=total_time,
                        start_time=time.ctime(start_ts),
                        file_path=file_path,
                        hide=True,
                        file_write='w'
                    )

                    time.sleep(0.5)
                
                avg_time = int(total_time / iterations)
                resolver_stats[domain] = avg_time

                print(domain + ' done, avg time = ', str(avg_time) + ' msec')
        else:
            # Use a custom DNS Resolver
            dns_ip = args[0].split('=')[1]
            resolver_stats = {}

            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ dns_ip ]
            
            for domain in websites:
                total_time = 0.0
                for i in range(iterations):
                    start_ts = time.time()

                    ans = dns.resolver.resolve(domain, 'A')

                    end_ts = time.time()

                    total_time += int((end_ts - start_ts) * 1000) # msec

                    time.sleep(0.5)
            
                avg_time = int(total_time / iterations)
                resolver_stats[domain] = avg_time

                print(domain + ',' + str(avg_time))
    except Exception as e:
        print(e)



