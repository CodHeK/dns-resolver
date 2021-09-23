CS534 - Assignment 1 (DNS/DNSSec)

Installation:

- Without virtual environment:

$ pip3 install -r requirements.txt

- Using a virtual environment (Better):

$ virtualenv venv
$ . venv/bin/activate
$ pip3 install -r requirements.txt


- File Structure:

ajjikuttira-gagan-ganapathy-HW1
│   README.txt
│   mydig.py  // ENTRYPOINT INTO THE PROJECT
│   custom_resolver.py  // IMPLEMENTS HELPER METHODS FOR BOTH RESOLVERS
|   dns_resolvers.py // DNS RESOLVER IMPLEMENTATION
|   dnssec_resolvers.py // DNSSEC RESOLVER IMPLEMENTATION
|   ...
|   performance_test.py // MEASURE PERFORMANCE AND STORE IN CSV
|   performance_report.py // GENERATE CDF OF THE DNS RESOLUTION TIMES
|   ...
|   mydig_output.txt // EXAMPLE OUTPUTS FOR A, NS, MX RECORDS USING A DNS RESOLVER
|   mydig_output_dnssec.txt // EXAMPLE OUTPUTS FOR A, NS, MX RECORDS USING A DNSSEC RESOLVER
└───


- Example commands (Using python v3.8.2):

- Running the DNS resolver:

$ ./mydig.py cnn.com A

$ ./mydig.py google.com NS

$ ./mydig.py amazon.com MX


- Running the DNSSEC resolver: (Just add the --dnssec flag to your queries)

$ ./mydig.py verisigninc.com A --dnssec

$ ./mydig.py verisigninc.com NS --dnssec

$ ./mydig.py exmaple.com MX --dnssec


NOTE:
- If incase the `./mydig.py` doesn't work, `cd` into your working directory and run

$ chmod +x mydig.py

now try running the script as `./mydig.py`

OR try running the project using `python3 mydig.py ...`


- Externel Libraries used:

- matplotlib (3.4.3)
- numpy (1.21.2)
- pandas (1.3.3)
- dnspython (2.1.0)
- sys
- time