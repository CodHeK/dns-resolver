import dns.rdatatype
from enum import Enum


RDATATYPE_MAP = {
    dns.rdatatype.NS: 'NS',
    dns.rdatatype.A: 'A',
    dns.rdatatype.MX: 'MX',
    dns.rdatatype.CNAME: 'CNAME',
}

class DNSSEC_STATUS_CODES(Enum):
    VERIFICATION_FAILED = 0
    SUPPORTED = 1
    NOT_SUPPORTED = 2