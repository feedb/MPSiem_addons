########################################################################################
#                                                                                      #  
#                                  get ES params for search statistics                 #  
#                                                                                      #  
########################################################################################

import json
import argparse
import json

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
args = parser.parse_args()
es_request = "http://{}:9200/_stats/search".format(args.siemaddress)
loaded_json = json.loads(urlopen(es_request).readline())
result = []
for index_name in loaded_json["indices"]:
    index_stat = loaded_json["indices"][index_name]["primaries"]["search"]
    #add to result only non zero result
    if index_stat["query_time_in_millis"] > 0:
        index_stat.update({"index": index_name})
        #add calculated field: average for query, fetch and scroll
        query_avg = fetch_avg = scroll_avg = 0
        if index_stat["query_total"] > 0:
            query_avg = round(index_stat["query_time_in_millis"] / index_stat["query_total"], 2)
        if index_stat["fetch_total"] > 0:
            fetch_avg = round(index_stat["fetch_time_in_millis"]/index_stat["fetch_total"], 2)
        if index_stat["scroll_total"] > 0:
            scroll_stat = round(index_stat["scroll_time_in_millis"]/index_stat["query_total"], 2)
        index_stat.update({"query_avg_in_millis": query_avg})
        index_stat.update({"fetch_avg_in_millis": fetch_avg})
        index_stat.update({"scroll_avg_in_millis": scroll_avg})
        result.append(index_stat)

print(json.dumps(result))
