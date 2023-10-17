from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD, MODIFY_REPLACE
from impacket.structure import Structure
import socket
import dns.resolver
import datetime
import argparse


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

def new_record(rtype):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = get_next_serial(dc_ip, domain)
    nr['TtlSeconds'] = 180
    # From authoritive zone
    nr['Rank'] = 240
    return nr

def get_next_serial(dc, zone):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    dnsresolver.nameservers = [dc]

    res = dnsresolver.resolve(zone, 'SOA',tcp=False)
    for answer in res:
        return answer.serial + 1


def parse_arguments():
    parser = argparse.ArgumentParser(description="Process some arguments")
    parser.add_argument('-d', '--domain', required=True, help='Domain name of the target system.')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication.')
    parser.add_argument('-p', '--password', required=True, help='Password for authentication.')
    parser.add_argument('--dc-ip', required=True, help='IP address of the Domain Controller.')
    parser.add_argument('-s', '--secure', action='store_true', help='Use SSL for secure communication.')
    parser.add_argument('-M', '--module', required=True, choices=module_functions.keys(), help='Specify the module to execute.')
    parser.add_argument('--data', nargs='+', help='Additional data to pass to the specified module.')
    args = parser.parse_args()

    return args


def get_entries():
    filter = "(objectClass=*)"
    connection.search(search_base=dnsroot, search_filter=filter, search_scope=SUBTREE)
    entries = connection.entries
    return [entry.entry_dn for entry in entries if "._tcp" not in entry.entry_dn and "._udp" not in entry.entry_dn]


def get_raw_entry(target):
    filter = f'(&(objectClass=dnsNode)(name={target}))'
    connection.search(search_base=dnsroot, search_filter=filter, attributes=['dnsRecord','dNSTombstoned','name'])
    for entry in connection.response:
        if entry['type'] != 'searchResEntry':
            continue
        return entry


def get_entry(target):
    record_data = get_raw_entry(target)['raw_attributes']['dnsRecord'][0][-4:]
    parsed_record = DNS_RPC_RECORD_A(record_data)
    ip_address = parsed_record.formatCanonical()
    return {'name': get_raw_entry(target)['attributes']['name'], 'ip': ip_address}


def add_entry(target, data):
    record_dn = f'DC={target},{dnsroot}'
    node_data = {
        # Schema is in the root domain (take if from schemaNamingContext to be sure)
        'objectCategory': f'CN=Dns-Node,CN=Schema,CN=Configuration,{domainroot}',
        'dNSTombstoned': False,
        'name': target
    }
    record = new_record(1)
    record['Data'] = DNS_RPC_RECORD_A()
    record['Data'].fromCanonical(data)
    node_data['dnsRecord'] = [record.getData()]
    connection.add(record_dn, ['top', 'dnsNode'], node_data)
    return get_entry(target)


def modify_entry(target, data):
    targetentry = get_raw_entry(target)
    records = []
    for record in targetentry['raw_attributes']['dnsRecord']:
        dr = DNS_RECORD(record)
        if dr['Type'] == 1:
            targetrecord = dr
        else:
            records.append(record)
    targetrecord['Serial'] = get_next_serial(dc_ip, domain)
    targetrecord['Data'] = DNS_RPC_RECORD_A()
    targetrecord['Data'].fromCanonical(data)
    records.append(targetrecord.getData())
    connection.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, records)]})
    return get_entry(target)


def del_entry(target):
    targetentry = get_raw_entry(target)
    diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
    tstime = int(diff.total_seconds()*10000)
    # Add a null record
    record = new_record(0)
    record['Data'] = DNS_RPC_RECORD_TS()
    record['Data']['entombedTime'] = tstime
    connection.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],'dNSTombstoned': [(MODIFY_REPLACE, True)]})


if __name__ == "__main__":
    module_functions = {
        'get_entries': get_entries,
        'get_entry': get_entry,
        'add_entry': add_entry,
        'modify_entry': modify_entry,
        'del_entry': del_entry
    }

    args = parse_arguments()

    domain = args.domain
    username = args.username
    sam = f"{username}@{domain}"
    password = args.password
    dc_ip = args.dc_ip

    domainroot = f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"
    dnsroot = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}"

    if args.secure:
        dc_url = f"ldaps://{dc_ip}:636"
    else:
        dc_url = f"ldap://{dc_ip}:389"

    server = Server(dc_url, get_info=ALL)
    connection = Connection(server, user=sam, password=password, auto_bind=True)

    module = args.module
    selected_function = module_functions.get(module, None)

    if args.data:
        print(selected_function(*args.data))
    else:
        print(selected_function())