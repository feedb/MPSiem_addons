#!/usr/bin/env python
#  coding=utf-8

import subprocess
import re
import json


fpta_path = '/opt/mpxsiem/fpta/'
fpta_dbs=['fpta_enricher.db','core_db.db','fpta_db.db']
json_arr=[]

for fpta_db in fpta_dbs:

    command_line = "{0}mdbx_stat -nef {0}{1} | grep -E \"^\s+.*:\" | awk '{{$1=$1;print}}'".format(fpta_path,fpta_db)
    output = ( subprocess.check_output(command_line, shell = True) )
    lines = output.splitlines()

    for line in lines:

        name,data = line.split(":")
        name = name.replace(' ', '_')

        value = 0
        result = re.search(r'[0-9]+',data)
        if (result): value = int( result.group(0) )

        percent = 0
        result = re.search(r'([0-9.]+)(\%)',data)
        if (result): 
            try:
                percent =  float(result.group(1))
            except:
                percent = 0
        json_arr.append( {"value": value, "percent": percent,"fpta_db":fpta_db,"fpta_param": name,"measurement":"fpta_stat"})

print json.dumps(json_arr)

