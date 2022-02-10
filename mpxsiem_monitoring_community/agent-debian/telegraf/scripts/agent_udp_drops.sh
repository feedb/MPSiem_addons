#!/bin/bash
#get udp data srat and formatting
data_lines=$(cat /proc/net/udp | tr -s ": " " " | awk -F' ' '/[0-9]/ {printf "%d:%d:%d \n", "0x" $3, "0x" $8, $NF}')

#make json for output in cycle
result_json="["
for line in $data_lines
do
    IFS=':' read -r -a val<<<"$line"
    #convert signed value to unsigned
    if [[ ${val[2]} -lt 0 ]]; then
            unsigned_val=$((4294967296+${val[2]}))
    else
            unsigned_val=${val[2]}
    fi
    result_json+="{\"local_port\":\"${val[0]}\",\"rx_queue_length\": ${val[1]},\"drops_count\": $unsigned_val},"
done

#drop last symbol "," and add closed bracket
result_json=$(echo $result_json | rev| cut -c 2- | rev)
result_json+="]"
echo $result_json
