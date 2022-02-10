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

raw_addr="http://{}:8013/events/counter/simple?name=storage.events_raw.in&granularity=300&aggregation=avg".format(args.siemaddress)
norm_addr="http://{}:8013/events/counter/simple?name=storage.events_norm.in&granularity=300&aggregation=avg".format(args.siemaddress)
corrin_addr="http://{}:8013/events/counter/simple?name=correlator.events.in&granularity=300&aggregation=avg".format(args.siemaddress)
corrout_addr="http://{}:8013/events/counter/simple?name=correlator.events.out&granularity=300&aggregation=avg".format(args.siemaddress)
parsed_string_r = json.loads(urlopen(raw_addr).read())
parsed_string_n = json.loads(urlopen(norm_addr).read())
parsed_string_ci = json.loads(urlopen(corrin_addr).read())
parsed_string_co = json.loads(urlopen(corrout_addr).read())
r_str=parsed_string_r["count"]
n_str=parsed_string_n["count"]
ci_str=parsed_string_ci["count"]
co_str=parsed_string_co["count"]
metric_list = [r_str, n_str, ci_str, co_str]
new_list = []
for item in metric_list:
    if len(item) > 2:
        new_list.append(item[-2])
    else:
        new_list.append(0)

print(json.dumps([{'raw_eps':round(new_list[0])}, {'norm_eps':round(new_list[1])}, {'corr_in':round(new_list[2])}, {'corr_out':round(new_list[3])}]))
 

