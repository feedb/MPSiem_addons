import os
import sys

def get_folder_size(path):
  size = 0
  for dirpath, dirnames, filenames in os.walk(path):
    for f in filenames:
        fp = os.path.join(dirpath, f)
        size += os.path.getsize(fp)
  return size

folders_arr=[
       "/opt/mpagent/data",
       "/opt/mpagent/queue_dir",
       "/opt/mpagent/storage_dir"
        ]

out_json='['
for p in folders_arr:
    out_json +="{{ \"dir_size_bytes\": {0}, \"dir_path\": \"{1}\"}},".format(get_folder_size(p),p)

print("{}]".format(out_json[:-1]))
