 #!/usr/bin/env python3
 # -*- coding: utf-8 -*-

from __future__ import print_function
import ldap3, argparse, sys, yaml, re, json, time, colorama, os
import datetime, time

#Python 2 hack to force utf8 encoding
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

colorama.init()

def ldap_time_stamp(dt):
    MagicNumber = 116444736000000000
    return str(int(time.mktime(dt.timetuple()) *10000000) + MagicNumber)

epilog = os.linesep.join([
    'Custom Searches:',
    '\t  1) Get all users',
    '\t  2) Get all groups (and their members)',
    '\t  3) Get all printers',
    '\t  4) Get all computers',
    '\t  5) Search for Unconstrained SPN Delegations (Potential Priv-Esc)',
    '\t  6) Search for Accounts where PreAuth is not required. (ASREPROAST)',
    '\t  7) All User SPNs (KERBEROAST)',
    '\t *8) Show All LAPS LA Passwords (that you can see)',
    '\t  9) Show All Quest Two-Factor Seeds (if you have access)',
    '\t 10) Oracle "orclCommonAttribute" SSO password hash',
    '\t*11) Oracle "userPassword" SSO password hash' 
    '\n',
    'Starred items have never been tested in an environment where they could be verified, so please let me know if they work.'
])

    
custom_search = [
    ['(objectcategory=user)', 'cn', 'mail', 'memberOf', 'sAMAccountName'], #Users
    ['(objectclass=group)', 'member'], #Groups
    ['(objectCategory=printeQueue)'], #Printers
    ['(&(objectCategory=computer)(lastLogonTimestamp>=' + ldap_time_stamp(datetime.datetime.today() - datetime.timedelta(days=90)) + '))', 'dNSHostName', 'description', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'servicePrincipalName', 'lastLogonTimestamp'], #Computers
    ['(userAccountControl:1.2.840.113556.1.4.803:=524288)', 'cn', 'servicePrincipalName'], #Unconstrained Delegation
    ['(userAccountControl:1.2.840.113556.1.4.803:=4194304)', 'cn', 'distinguishedName'], #PreAuth Not Required
    ['(&(objectcategory=user)(serviceprincipalname=*))', 'userPrincipalName', 'servicePrincipalName'], #User SPNs
    ['(ms-Mcs-AdmPwd=*)', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'], #LAPS LA Passwords
    ['(defender-tokenData=*)'], #Defender Token Data
    ['(&(objectcategory=user)(orclCommonAttribute=*))', 'cn', 'memberOf', 'sAMAccountName', 'orclCommonAttribute'], #orclCommonAttribute SSO hash1
    ['(&(objectcategory=user)(userPassword=*))', 'cn', 'memberOf', 'sAMAccountName', 'userPassword'], #Oracle userPassword SSO hash2
]

parser = argparse.ArgumentParser(description="AD LDAP Command Line Searching that doesn't suck.", epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--domain', '-D', help='Domain')
parser.add_argument('--user', '-U', help='Username')
parser.add_argument('--password', '-P', help='Password')
parser.add_argument('--server', '-S', help='DC IP or resolvable name (can be comma-delimited list for round-robin)')
parser.add_argument('--basedn', '-b', help='Base DN should typically be "dc=", followed by the long domain name with periods replaced with ",dc="')
parser.add_argument('--search', '-s', help='LDAP search string or number indicating custom search from "Custom Searches" list')
parser.add_argument('--maxrecords', '-m', help='Maximum records to return (Default is 100), 0 means all.', default=100, type=int)
parser.add_argument('--pagesize', '-p', help='Number of records to return on each pull (Default is 10).  Should be <= max records.', default=10, type=int)
parser.add_argument('--delay', '-d', help='Millisecond delay between paging requests (Defaults to 0).', default=0, type=int)
parser.add_argument('--format', '-f', help='Format of output (Default is "plain"), can be: plain, json. json_tiny', default='plain', choices=['plain', 'json', 'json_tiny'])
parser.add_argument('--encryption', '-n', help="3) Connect to 636 TLS (Default); 2) Connect 389 No TLS, but attempt STARTTLS and fallback as needed; 1) Connect to 389, Force Plaintext", default=3, type=int, choices=[1, 2, 3]) 
parser.add_argument('attributes', metavar='attribute', nargs='*', help='Attributes to return (defaults to all)')

args = parser.parse_args()  

if len(sys.argv) == 1:
    parser.print_help()
    exit(-1)

    
ldap3.set_config_parameter('DEFAULT_ENCODING', 'utf-8')
    
servers = [server.strip() + (':636' if args.encryption == 3 else ':389') for server in args.server.split(',')]

if args.encryption == 3:
    server = ldap3.Server(*servers, get_info=ldap3.ALL, use_ssl=True)
else:
    server = ldap3.Server(*servers, get_info=ldap3.ALL)

if args.search.isdigit():
    option = int(args.search)
    if option > 0 and option <= len(custom_search):
        args.search = custom_search[option - 1][0]
        
        if len(custom_search[option - 1]) > 1 and args.attributes == []:
            args.attributes = custom_search[option - 1][1:]

if len(args.attributes) > 0:
    args.attributes.append('cn')
    args.attributes = set(map(str.lower, args.attributes))


with ldap3.Connection(server, user=r'%s\%s' % (args.domain, args.user), password=args.password, authentication=ldap3.NTLM, read_only=True) as conn:
    if args.encryption == 2:
        try:
            conn.start_tls()
        except:
            print((colorama.Fore.YELLOW + '\n%s\n' + colorama.Style.RESET_ALL) %'NOTICE: Unable to use STARTTLS', file=sys.stderr)
 
    if not conn.bind():
        print((colorama.Fore.RED + '\n%s\n' + colorama.Style.RESET_ALL) %'ERROR: An error occurred while attempting to connect to the server(s).  If the ip(s) are correct, your credentials are likely invald', file=sys.stderr)
        exit(-1)
    
    i = 0
    
    pagesize = 10 if args.pagesize <= 0 else args.pagesize
    maxrecords = 100 if args.maxrecords < 0 else args.maxrecords
    pagesize = min(maxrecords, pagesize) if maxrecords != 0 else pagesize

    cookie = True
    looptrack = ""
    
    conn.search(args.basedn, args.search, search_scope=ldap3.SUBTREE, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES], paged_size=pagesize)
    
    while cookie:
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        
        for entry in conn.entries:
            printable_entry =json.loads(entry.entry_to_json())
            
            if len(args.attributes) > 0:
                attributes = {x.lower():x for x in printable_entry['attributes']}
                printable_entry['attributes'] = {attributes[x]:printable_entry['attributes'][attributes[x]] for x in args.attributes if x in attributes}
            
            if looptrack == "":
                looptrack = printable_entry['dn']
            elif looptrack == printable_entry['dn']:
                #in spite of cookie paging, AD starts looping forever
                cookie = False
                break
            
            i += 1
           
            if args.format in ['json', 'json_tiny']:
                if i == 1:
                    print("[", end='')
                else:
                    print(",", end='')

            if args.format == 'json':
                print(json.dumps(printable_entry, indent=4, sort_keys=True))
            elif args.format == 'json_tiny':
                print(json.dumps(printable_entry, ensure_ascii=False), end='')
            else:
                print(printable_entry['dn'])
                if 'attributes' in printable_entry:
                    #ugly hacks abound to deal with objects containig unserializabl data and to to pretty print the attributes
                    try:
                        print(re.sub(r'^', r'  ', re.sub(r'^(\s*)-', r'\1 ', yaml.safe_dump(yaml.safe_load(json.dumps(printable_entry['attributes'], ensure_ascii=False)), allow_unicode=True, default_flow_style=False),  flags=re.M),  flags=re.M))
                    except:
                        print('Character Encoding Error.')            

            if maxrecords > 0 and i >= maxrecords:
                print((colorama.Fore.YELLOW + '\n%s\n' + colorama.Style.RESET_ALL) % 'NOTICE: Search returned at least as many records as maxrecords argument allowed.  You may be missing results.', file=sys.stderr)
                break
        
        if args.delay > 0:
            time.sleep(args.delay / 1000)
        
        if maxrecords != 0:
            pagesize = min((maxrecords - i), pagesize)
        
        conn.search(args.basedn, args.search, search_scope=ldap3.SUBTREE, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES], paged_size=pagesize, paged_cookie=cookie)
        
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        
if i == 0:
    print((colorama.Fore.YELLOW + '\n%s\n' + colorama.Style.RESET_ALL) % 'NOTICE: No results were returned for your query', file=sys.stderr)
elif args.format in ['json', 'json_tiny']:
    print("]", end='', flush=True)
