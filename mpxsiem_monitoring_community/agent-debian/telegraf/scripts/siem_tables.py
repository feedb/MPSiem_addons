import json
import argparse

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

def setup_args():
    parser = argparse.ArgumentParser(
        description='Arguments for connect to SIEM Server')

    parser.add_argument('-s', '--siemaddress',
                        required=False,
                        default='localhost',
                        help='MaxPatrol SIEM Server address(ip or fqdn), default is localhost'
                        )
    return parser


parser = setup_args()
args = parser.parse_args()
tables_request="http://{}:8013/v2/control/tables".format(args.siemaddress)
parsed_string = json.loads(urlopen(tables_request).read())
print(json.dumps(parsed_string))
#print(json.dumps([{'raw_eps':round(new_list[0])}, {'norm_eps':round(new_list[1])}, {'corr_in':round(new_list[2])}, {'corr_out':round(new_list[3])}]))
 

