def output(**kwargs):
    OUTPUT_FILE = 'mydig_output.txt'
    
    domain_name = kwargs['domain_name']
    dns_query_type = kwargs['dns_query_type']
    response = kwargs['response']
    query_time = kwargs['query_time']
    start_time = kwargs['start_time']
    hide = kwargs.get('hide', False)

    output_str = '''\nQUESTION SECTION:\n{domain_name}\t\tIN\t{dns_query_type}\n\nANSWER SECTION:\n'''.format(
        domain_name=domain_name, 
        dns_query_type=dns_query_type
    )

    for ip, dtype, query_name in response:
        output_str += '''{query_name}\tIN\t{dtype} \t{ip}\n'''.format(query_name=query_name, dtype=dtype, ip=ip)

    output_str += '\n'

    output_str += '''Query time: {query_time} msec\nWHEN: {start_time}\n'''.format(
        query_time=str(query_time),
        start_time=start_time
    )

    output_str += '''MSG SIZE rcvd: {output_str_len}'''.format(output_str_len=len(output_str))

    if not hide:
        print(output_str)

    if 'file_path' in kwargs:
        OUTPUT_FILE = kwargs['file_path']

    # f = open(OUTPUT_FILE, 'a' if 'file_write' not in kwargs else kwargs['file_write'])
    # f.write(output_str)
    # f.close()

    
