import html
import re
import json
import time
import os.path
import requests
import sys

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
    msg += "[" + inc["key"] +"](" + url + ")  [" + inc['name'] + "]"
    #https:// text part didn't work for me when passing in HTML parse_mode
    requests.post("https://api.telegram.org/bot" + settings['token'] + "/sendMessage", data = {'chat_id': settings['chat_id'], 'text':msg, 'parse_mode': 'Markdown'})
  
if __name__ == "__main__":
    settings = {}
    settings['logfile'] = 'processed_incident_list.log'
    settings['core_url'] = 'https://'   #https://maxpatrolsiemaddress
    settings['core_user'] = ''  #Administrator
    settings['core_pass'] = ''  #P@ssw0rd
    settings['time_from'] = 600 #in the last 10 minutes
    settings['token'] = ''
    settings['chat_id'] = ''
    
    session = authenticate(settings['core_url'], settings['core_user'], settings['core_pass'])[0]
    sent_list = read_incident_file(settings['logfile'])
    unix_time = int(time.time()) - settings['time_from']
    post_params = r'{"offset":0,"limit":50,"groups":{"filterType":"no_filter"},"timeFrom":' + str(unix_time) + \
                  r',"timeTo":null,"filterTimeType":"creation","filter":{"select":["key","name","category",' + \
                  r'"type","status","created","assigned"], "where":"","orderby":[{"field":"created",' + \
                  r'"sortOrder":"descending"}, {"field":"status","sortOrder":"ascending"},' + \
                  r'{"field":"severity","sortOrder":"descending"}]},"queryIds":["all_incidents"]}'
    res = session.post(settings['core_url'] + '/api/v2/incidents/', json=json.loads(post_params)).text
    
    recv_list = []
    for inc in (reversed(json.loads(res)["incidents"])):
        if not sent_list or (int(sent_list[-1]) < int(inc["key"].split('-')[-1])):
            send_telegram_message(inc, settings)
            recv_list.append(inc["key"].split('-')[-1])     
    if recv_list:
        write_incident_file(settings['logfile'], recv_list[-1])
