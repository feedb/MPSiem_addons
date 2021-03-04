import psycopg2
import glob
import json
import ast
import os
import datetime

cfg_folder_mask = os.path.dirname(os.path.realpath(__file__))+"/pg_stat/*.json"

_PG_USER_ = "pt_system"
_PG_PASS_ = "P@ssw0rdP@ssw0rd0"
_PG_PORT_ = "5432"
_PG_ADDRESS_ = "127.0.0.1"

def json_from_file(filename):
    with open(filename) as json_file:
        try:
            data = json.loads( json_file.read() )
        except ValueError:
            data = {}
            
    return data


def get_database_value( dbase, query, val = 0 ):
    
    ret_json = {"value":0, "error":0}
    query = query.replace("{val}",str(val))
        
    try:
        conn = psycopg2.connect( database = dbase, user = _PG_USER_, password = _PG_PASS_, host=_PG_ADDRESS_, port=_PG_PORT_ )
    except:
        ret_json["error"] = 1
    
    if (not ret_json["error"]):
        try:
            
            cur=conn.cursor()
            cur.execute( query )
            query_results = cur.fetchall()
            cur.close()
            conn.close()
        except:
            
            ret_json["error"] = 2
            query_results = [] 
    if  query_results and ( len(query_results[0])>0 ):
        ret_json["value"] = query_results[0][0]
    
    return ret_json    
    

#get data for every json file
all_jsons = []                       #collect all dashboard data for send to influxDB
errors_json = {"dashboard":"errors"} #collect error in dashboards queries for send to InfluxBD 

for file in glob.glob(cfg_folder_mask):

    json_data = json_from_file(file)
        
    if json_data:
        out_json= {"dashboard":json_data["dashboard"],
                    "value":0,
                    "lag":0}
        
        #get value from first query
        query_result = get_database_value( json_data["database1"], json_data["query1"] ) 
        out_json["value"] = int( query_result["value"])
        err = query_result["error"]
        
        #Calculate lag based on second query with value  from first as param
        #two variants: direct second query result or diff queries 1 2 result
        query_result =  get_database_value( json_data["database2"], json_data["query2"], out_json["value"] )
        if ( ("lag_is_diff" in json_data) and (json_data["lag_is_diff"]) ):
            out_json["lag"] = abs ( int(out_json["value"]) - int(query_result["value"]) )
        else:
            out_json["lag"]  = int( query_result["value"] )
        
        #errors summary
        if (not err): err = query_result["error"]
        
        #form special records for dashboards error control: "err_dashboard":{0:1}
        errors_json[f'err_{json_data["dashboard"]}'] = err
        all_jsons.append(out_json)

all_jsons.append(errors_json)

#Send all data to InfluxDB
print(json.dumps(all_jsons))
