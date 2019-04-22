import html
import re
import json
import time
import os.path
import requests
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import _mssql
import decimal
import socket
from collections import OrderedDict
from os import getenv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SQL_BROWSER_DEFAULT_PORT = 1434


class AccessDenied(Exception):
    pass


def authenticate(address, login, password, new_password=None, auth_type=0):
    session = requests.session()
    session.verify = False

    response = print_response(session.post(
        address + ':3334/ui/login',
        json=dict(
            authType=auth_type,
            username=login,
            password=password,
            newPassword=new_password
        )
    ), check_status=False)

    if response.status_code != 200:
        raise AccessDenied(response.text)

    if '"requiredPasswordChange":true' in response.text:
        raise AccessDenied(response.text)

    return session, available_applications(session, address)


def available_applications(session, address):
    applications = print_response(session.get(
        address + ':3334/ptms/api/sso/v1/applications'
    )).json()

    return [
        app['id']
        for app in applications
        if is_application_available(session, app)
    ]


def is_application_available(session, app):
    if app['id'] == 'idmgr':
        modules = print_response(session.get(
            app['url'] + '/ptms/api/sso/v1/account/modules'
        )).json()

        return bool(modules)

    if app['id'] == 'mpx':
        return external_auth(
            session,
            app['url'] + '/account/login?returnUrl=/#/authorization/landing'
        )


def external_auth(session, address):

    response = print_response(session.get(address))

    if 'access_denied' in response.url:
        return False

    while '<form' in response.text:
        form_action, form_data = parse_form(response.text)

        response = print_response(session.post(form_action, data=form_data))

    return True


def parse_form(data):
    return re.search('action=[\'"]([^\'"]*)[\'"]', data).groups()[0], {
        item.groups()[0]: html.unescape(item.groups()[1])
        for item in re.finditer(
            'name=[\'"]([^\'"]*)[\'"] value=[\'"]([^\'"]*)[\'"]',
            data
        )
    }


def print_response(response, check_status=True):
    if check_status:
        assert response.status_code == 200
    return response


def read_incident_file(file_name):
    incident_list = []
    if not os.path.exists(file_name):
        return []
    with open(file_name, "r") as fh:
        for line in fh:
            incident_list.append(line.rstrip())
    return incident_list


def write_incident_file(file_name, incident):
    with open(file_name, "w") as fh:
        fh.write(incident + "\n")


def send_telegram_message(inc, settings):
    url = settings['core_url'] + """/#/incident/incidents/view/""" + inc["id"]
    msg = ""
    msg += "[" + inc["key"] + "](" + url + ")  [" + inc['name'] + "]"
    # https:// text part didn't work for me when passing in HTML parse_mode
    requests.post("https://api.telegram.org/bot" + settings['token'] + "/sendMessage", data={
                  'chat_id': settings['chat_id'], 'text': msg, 'parse_mode': 'Markdown'})


def get_db_data_size(db_user, db_password, db_server, db_port, db_name):
    conn = _mssql.connect(server=db_server, user=db_user,
                          password=db_password, database=db_name, port=str(db_port))
    #conn.execute_query("USE " + db_name + "; EXEC sp_spaceused;")
    size = conn.execute_query("USE " + db_name + "; EXEC sp_spaceused;")
    res1 = [row for row in conn]       # 1st result
    res2 = [row for row in conn]       # 2nd result
    conn.close()
    return res2


def get_db_size(db_user, db_password, db_server, db_port, db_name):
    conn = _mssql.connect(server=db_server, user=db_user,
                          password=db_password, database=db_name, port=str(db_port))
    #conn.execute_query("USE " + db_name + "; EXEC sp_spaceused;")
    size = conn.execute_query("USE " + db_name + "; EXEC sp_spaceused;")
    res1 = [row for row in conn]       # 1st result
    res2 = [row for row in conn]       # 2nd result
    conn.close()
    return int(float(res1[0]['database_size'].split(' ')[0]))


def get_db_data_size_debug(db_user, db_password, db_server, db_port, db_name):
    conn = _mssql.connect(server=db_server, user=db_user,
                          password=db_password, database=db_name, port=str(db_port))
    #conn.execute_query("USE " + db_name + "; EXEC sp_spaceused;")
    size = conn.execute_query("USE " + db_name + "; EXEC sp_spaceused;")
    res1 = [row for row in conn]       # 1st result
    res2 = [row for row in conn]       # 2nd result
    conn.close()
    print("database_size: " + res1[0]['database_size'] + "   reserved: " + str(round(int(res2[0]['reserved'].split(' ')[0]) / 1024)) + "   data: " + str(round(int(res2[0]['data'].split(
        ' ')[0]) / 1024)) + "   index_size: " + str(round(int(res2[0]['index_size'].split(' ')[0]) / 1024)) + "   unused: " + str(round(int(res2[0]['unused'].split(' ')[0]) / 1024)))
    return 1


def get_db_busy(db_user, db_password, db_server, db_port, db_name):
    conn = _mssql.connect(server=db_server, user=db_user,
                          password=db_password, database=db_name, port=str(db_port))
    res = conn.execute_row(
        "SELECT * FROM sys.dm_exec_requests  WHERE command='DELETE';")
    if res == None:
        return 0
    else:
        return 1


def shrink_db(db_user, db_password, db_server, db_port, db_name):
    conn = _mssql.connect(server=db_server, user=db_user,
                          password=db_password, database=db_name, port=str(db_port))
    res = conn.execute_query("DBCC SHRINKDATABASE ('" + db_name + "', 1);")


def get_instance_info(host, instance=None, sql_browser_port=SQL_BROWSER_DEFAULT_PORT,
                      buffer_size=4096, timeout=15):
    """Gets Microsoft SQL Server instance information by querying the SQL Browser service.

    Args:
        host (str): Hostname or IP address of the SQL Server to query for information.
        instance (str): The name of the instance to query for information.
                        All instances are included if none.
        sql_browser_port (int): SQL Browser port number to query.
        buffer_size (int): Buffer size for the UDP request.
        timeout (int): timeout for the query.

    Returns:
        dict: A dictionary with the server name as the key and a dictionary of the
            server information as the value.

    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set a timeout
    sock.settimeout(timeout)

    server_address = (host, sql_browser_port)

    if instance:
        # The message is a CLNT_UCAST_INST packet to get a single instance
        # https://msdn.microsoft.com/en-us/library/cc219746.aspx
        message = '\x04%s\x00' % instance
        # Encode the message as a bytesarray
    else:
        # The message is a CLNT_UCAST_EX packet to get all instances
        # https://msdn.microsoft.com/en-us/library/cc219745.aspx
        message = '\x03'

    # Encode the message as a bytesarray
    message = message.encode()

    # Send data
    sock.sendto(message, server_address)

    # Receive response
    data, server = sock.recvfrom(buffer_size)

    results = []

    # Loop through the server data
    for server in data[3:].decode().split(';;'):
        server_info = OrderedDict()
        chunk = server.split(';')

        if len(chunk) > 1:
            for i in range(1, len(chunk), 2):
                server_info[chunk[i - 1]] = chunk[i]

            results.append(server_info)

    # Close socket
    sock.close()

    instance_info = dict(zip(results[0].keys(), results[0].values()))
    db_port = int(instance_info['tcp'])
    return db_port


def delete_rows(db_user, db_password, db_server, db_port, db_name, available_space, min_free_space):

    session = authenticate(settings['core_url'], settings['core_user'], settings[
                           'core_pass'], auth_type=settings['auth_type'])[0]
    unix_time = 0
    post_params = r'{"offset":0,"limit":1,"groups":{"filterType":"no_filter"},"timeFrom":' + str(unix_time) + \
                  r',"timeTo":null,"filterTimeType":"creation","filter":{"select":["key","name","category",' + \
                  r'"type","status","created","assigned"], "where":"","orderby":[{"field":"created",' + \
                  r'"sortOrder":"descending"}, {"field":"status","sortOrder":"ascending"},' + \
                  r'{"field":"severity","sortOrder":"descending"}]},"queryIds":["all_incidents"]}'
    res = session.post(
        settings['core_url'] + '/api/v2/incidents/', json=json.loads(post_params)).text

    db_total_items = int(json.loads(res)["totalItems"])

    if (db_total_items - 1000) > 0:
        db_offset = db_total_items - 1000
    else:
        db_offset = 1

    post_params_2 = r'{"offset":' + str(db_offset) + ',"limit":1000,"groups":{"filterType":"no_filter"},"timeFrom":' + str(unix_time) + \
        r',"timeTo":null,"filterTimeType":"creation","filter":{"select":["key","name","category",' + \
        r'"type","status","created","assigned"], "where":"","orderby":[{"field":"created",' + \
        r'"sortOrder":"descending"}, {"field":"status","sortOrder":"ascending"},' + \
        r'{"field":"severity","sortOrder":"descending"}]},"queryIds":["all_incidents"]}'
    item_list = session.post(
        settings['core_url'] + '/api/v2/incidents/', json=json.loads(post_params_2)).text
    tems_list_json = json.loads(item_list)

    items_key = []
    for id in range(1, int(len(tems_list_json['incidents'])) + 1):
        id = int(len(tems_list_json['incidents'])) - id
        items_key.append(tems_list_json['incidents'][id]['key'])
    write_log(settings['log_file'], "Items in list: \n")
    write_log(settings['log_file'], items_key, type="list")

    db_size = get_db_size(db_user, db_password, db_server, db_port, db_name)
    db_data_size = round(int(get_db_data_size(
        db_user, db_password, db_server, db_port, db_name)[0]['data'].split(' ')[0]) / 1024)
    db_index_size = round(int(get_db_data_size(db_user, db_password, db_server, db_port, db_name)[
                          0]['index_size'].split(' ')[0]) / 1024)
    db_max_data_size = int((available_space - db_index_size)
                           * (100 - min_free_space) / 100)

    if db_size > available_space:
        if db_data_size > db_max_data_size:
            one_item_size = db_data_size / db_total_items  # in MB
            items_to_delete = int(
                (db_data_size - db_max_data_size) / (one_item_size * 1))
            listed_number_of_incidents = int(len(tems_list_json['incidents']))
            items_range = min([items_to_delete, listed_number_of_incidents])

            # debug output
            get_db_data_size_debug(db_user, db_password,
                                   db_server, db_port, db_name)
            print("listed_number_of_incidents: " + str(listed_number_of_incidents) + "   db_data_size: " + str(db_data_size) + " MB   items_to_delete: " +
                  str(items_to_delete) + "   items_range:" + str(items_range) + "   db_total_items: " + str(db_total_items) + "   db_max_data_size: " + str(db_max_data_size))
            # debug output

            items_id = []
            items_key = []
            for id in range(1, items_range + 1):
                id = listed_number_of_incidents - id
                items_id.append(tems_list_json['incidents'][id]['id'])
                items_key.append(tems_list_json['incidents'][id]['key'])
            post_params_3 = r'{"incidents":["' + '", "'.join(items_id) + '"]}'
            write_log(settings['log_file'], "Items to delete: \n")
            write_log(settings['log_file'], items_key, type='list')
            res_3 = session.post(settings[
                                 'core_url'] + '/api/v2/incidents/delete_by_ids', json=json.loads(post_params_3))
            # To define database usage
            time.sleep(1)
            while get_db_busy(db_user, db_password, db_server, db_port, db_name):
                time.sleep(1)
                print("ACT!")

            return items_id
        else:
            print("\nNothing to do. DB free space is more then limit")
            return 0
    else:
        print("\nNothing to do. Data base size is less then available space")
        return 0


def export_config_example(config_file_name):
    settings_example = {}
    settings_example['core_url'] = 'https://192.168.0.2'
    settings_example['core_user'] = 'Administrator'  # Administrator
    settings_example['core_pass'] = 'P@ssw0rd'  # P@ssw0rd
    settings_example['db_server'] = '192.168.0.2'
    settings_example['sql_browser_port'] = 1434
    settings_example['db_user'] = 'sa'
    settings_example['db_password'] = 'P@ssw0rdP@ssw0rd'
    settings_example['db_name'] = 'MaxPatrol_IncidentReadModel'
    settings_example['available_space'] = 10000  # in MB
    settings_example['min_free_space'] = 10  # in % from available_space
    settings_example['log_file'] = 'remove_rows.log'
    settings_example['auth_type'] = 0

    with open(config_file_name, 'w') as file:
        if os.path.exists(str(config_file_name)):
            json.dump(settings_example, file, indent=2)
            file.close


def set_config(config_file_name):
    with open(config_file_name, 'r') as file:
        settings = file.read()
        settings = json.loads(settings)
    file.close
    return settings


def write_log(file_name, log, type='text'):
    with open(file_name, 'a') as file:
        if os.path.exists(str(file_name)):
            for item in log:
                if type == 'text':
                    file.write("%s" % item)
                else:
                    file.write("%s\n" % item)
            file.close


if __name__ == "__main__":
    try:
        sys.argv[1]
    except IndexError:
        if os.path.exists('parameters'):
            print("\nUsing configuration file 'parameters'\n")
            settings = set_config('parameters')
            try:
                db_port = get_instance_info(
                    settings['db_server'], instance=None, sql_browser_port=settings['sql_browser_port'])
            except socket.error as error:
                sys.stderr.write('Connection to %s:%s failed: %s' % (
                    settings['db_server'], settings['sql_browser_port'], error))
                sys.exit(1)
            else:
                print('Successfully connected to %s:%s' %
                      (settings['db_server'], settings['sql_browser_port']))
            while delete_rows(settings['db_user'], settings['db_password'], settings['db_server'], db_port, settings['db_name'], settings['available_space'], settings['min_free_space']):
                a = 0
        else:
            print("Config file doesn't exist! \nTo get example use '" +
                  sys.argv[0].split('\\')[-1] + " get' parameter.")
    else:
        if sys.argv[1] == "get":
            try:
                sys.argv[2]
            except IndexError:
                export_config_example('parameters')
                print("\nConfig saved to file 'parameters'")
            else:
                export_config_example(str(sys.argv[2]))
                print("\nConfig saved to file '" + str(sys.argv[2]) + "'")
        elif sys.argv[1] == "set":
            try:
                sys.argv[2]
            except IndexError:
                print("\nNo config file defined!")
            else:
                if os.path.exists(str(sys.argv[2])):
                    print("\nUsing configuration file '" +
                          str(sys.argv[2]) + "'\n")
                    settings = set_config(str(sys.argv[2]))
                    try:
                        db_port = get_instance_info(
                            settings['db_server'], instance=None, sql_browser_port=settings['sql_browser_port'])
                    except socket.error as error:
                        sys.stderr.write('Connection to %s:%s failed: %s' % (
                            settings['db_server'], settings['sql_browser_port'], error))
                        sys.exit(1)
                    else:
                        print('Successfully connected to %s:%s' % (
                            settings['db_server'], settings['sql_browser_port']))
                    while delete_rows(settings['db_user'], settings['db_password'], settings['db_server'], db_port, settings['db_name'], settings['available_space'], settings['min_free_space']):
                        a = 0
                else:
                    print(
                        "\n" + str(sys.argv[2]) + " file doesn't exist! \nTo get config example use 'get' parameter.")
        elif sys.argv[1] == "shrink":
            db_port = get_instance_info(
                settings['db_server'], instance=None, sql_browser_port=settings['sql_browser_port'])
            shrink_db(settings['db_user'], settings['db_password'], settings[
                      'db_server'], db_port, settings['db_name'])
        elif "help" in sys.argv[1]:
            print("\nUsage:")
            print("%10s%-20s%-50s" % ("", sys.argv[0].split(
                '\\')[-1], "                - execute script and use file 'parameters' as config"))
            print("%10s%-20s%-50s" % ("", sys.argv[0].split(
                '\\')[-1], " get [filename] - save configuration to file, by default to 'parameters'"))
            print("%10s%-20s%-50s" % ("", sys.argv[0].split(
                '\\')[-1], " set filename]  - execute script and use file 'filename' as config"))
            print("%10s%-20s%-50s" %
                  ("", sys.argv[0].split('\\')[-1], " shrink         - shrink database"))
            print("%10s%-20s%-50s" %
                  ("", sys.argv[0].split('\\')[-1], " help           - to see this help"))
        else:
            print(
                "\nUnknown parameter 'sys.argv[1]'. Use: " + sys.argv[0].split('\\')[-1] + " help")
