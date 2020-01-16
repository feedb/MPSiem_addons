# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import unicode_literals
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, Alert, AlertArtifact, CustomFieldHelper
from cryptography.fernet import Fernet
import datetime
import html
import json
import os.path
import re
import requests
import sys
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KRAKOZYABRA = 'abToisdfas&asdf3451-l10asdfg-1451345121234dc='
CONFIG = "config.json"      # Название файла настроек скрипта
INC_PERIOD = 480            # Период мониторинга инцидентов (в секундах)
VERSION = 1.0               # Версия скрипта


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


def print_log(data):
    now = datetime.datetime.now()
    print(now.strftime("%Y-%m-%d %H:%M:%S") + ": " + str(data))


def read_processed_file(file_name):
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


def get_event(uuid, settings):
    res = settings['export_session'].get(settings['export_core_url'] +
                                         '/api/events/v2/events/' + uuid + '/normalized').json()

    # if settings['debug'] == 1:
    # print(res)
    # print(json.dumps(res, indent=4, sort_keys=True))

    if 'event' in res:
        return res['event']
    else:
        return None


def read_config_file():
    if not os.path.exists(CONFIG):
        print_log("ERROR: Can't find " + CONFIG)
        sys.exit(1)
    with open(CONFIG, encoding='utf-8') as fh:
        data = fh.read()
    return json.loads(data)


def get_incidents_list(settings):
    unix_time = int(time.time()) - settings['time_from']
    post_params = {
        "offset": 0,
        "limit": 75,  # Выгружаем не более 75 инцидентов
        "groups": {
            "filterType": "no_filter"
        },
        "timeFrom": unix_time,
        "timeTo": None,
        "filterTimeType": "creation",
        "filter": {
            "select": ["key",
                       "name",
                       "category",
                       "type",
                       "status",
                       "created",
                       "assigned"],
            "where": "",
            "orderby": [{
                "field": "created",
                "sortOrder": "descending"
            },
                {
                    "field": "status",
                    "sortOrder": "ascending"
                },
                {
                    "field": "severity",
                    "sortOrder": "descending"
                }]
        },
        "queryIds": ["all_incidents"]
    }
    res = settings['export_session'].post(
        settings['export_core_url'] + '/api/v2/incidents/', json=post_params).json()
    if "incidents" not in res:
        print_log("ERROR: getting incidents")
        update_time_from()
        sys.exit(0)
    if not res["incidents"]:
        print_log("INFO: no incidents found for export")
        sys.exit(0)
    return res


def login_api(settings):
    cipher_suite = Fernet(str.encode(KRAKOZYABRA))
    export_core_pass = cipher_suite.decrypt(
        settings['export_core_pass'].encode('utf-8')).decode()

    settings['export_session'] = authenticate(settings['export_core_url'], settings[
        'export_core_user'], export_core_pass, auth_type=settings['auth_type'])[0]


def get_inc_events(inc, settings):
    # Выгружаем не более 101 события привязанного с инциденту
    res = settings['export_session'].get(
        settings['export_core_url'] + '/api/incidents/' + inc["id"] + '/events?limit=101').json()
    try:
        if res:
            return res
    except:
        return []


def export_inc_to_alert(settings, api, incident, events, rec_list):
    descript = ('#### Cсылка в MP SIEM: **' + settings[
        'export_core_url'] + '/#/incident/incidents/view/' +
                incident["id"] + '?groupId=all_incidents&tabName=tasks**\n\n\n')
    if events is not None:
        event_counter = 0
        artifacts = []
        # print(json.dumps(events, indent=4, sort_keys=True))
        try:
            for event in events:
                event_norm = get_event(event["id"], settings)
                # print(json.dumps(event, indent=4, sort_keys=True))
                event_counter += 1
                descript += ('### Cобытие ' + str(event_counter) + ': **' + event_norm["id"] + '**\n\n' +
                             '|Поле           | Значение     |\n' +
                             '|---------------|:-------------|\n')

                try:
                    if event_norm["correlation_type"]:
                        title_alert = event_norm["text"]
                except KeyError:
                    pass

                observables_dict = {
                    'subject.name': 'other',
                    'object.name': 'other',
                    'src.ip': 'ip',
                    'dst.ip': 'ip',
                    'src.hostname': 'fqdn',
                    'dst.hostname': 'fqdn',
                    'event_src.host': 'fqdn'
                }

                for even in event_norm:
                    if str(even) != '_meta':
                        descript += '| **' + str(even) + '**| ' + str(event_norm[even]).replace("\n", "\\n"). \
                            replace("\r", "\\r").replace("|", "**OR**") + '|\n'
                        try:
                            artifacts.append(AlertArtifact(dataType=observables_dict[str(even)], data=event_norm[even]))
                        except:
                            pass

            # Prepare the custom fields
            customFields = CustomFieldHelper() \
                .add_string('category', incident["category"]) \
                .add_string('type', incident["type"]) \
                .build()

            # Словарь соответствия Severity в MP SIEM и The HIVE
            severity_dict = {'Low': 1, 'Medium': 2, 'High': 3}

            alert = Alert(title=title_alert + '    (' + str(event_counter) + ' Events)',
                          tlp=3,
                          tags=[incident["name"], incident["category"], incident["type"]],
                          description=descript,
                          type=incident["type"],
                          source='MP SIEM',
                          date=(incident["created"] * 1000),
                          sourceRef=str(incident["key"]),
                          severity=severity_dict[incident["severity"]],
                          artifacts=artifacts,
                          customFields=customFields)

            if event_counter > 1:
                response = api.create_alert(alert)
            else:
                update_time_from()
                sys.exit(0)

            if response.status_code == 201:
                # if settings['debug'] == 1:
                #     print(json.dumps(response.json(), indent=4, sort_keys=True))
                print_log("INFO: Export incident " + incident["key"] + " to HIVE alert **" + incident["name"] + "**")
                write_incident_file(settings['logfile'], rec_list[-1])
            else:
                print_log('ERROR: {}/{}'.format(response.status_code, response.text))
                update_time_from()
                if response.status_code == 500:
                    write_incident_file(settings['logfile'], rec_list[-1])
                sys.exit(0)

        except:
            print_log("WARNING: Export incident FAILED. Waiting.")
            update_time_from()
            sys.exit(0)
    else:
        print_log("WARNING: Incident without events. Waiting.")
        update_time_from()
        sys.exit(0)


def create_case_from_inc_name(api, incident):
    # Prepare the custom fields
    customFields = CustomFieldHelper() \
        .add_string('category', incident["category"]) \
        .add_string('type', incident["type"]) \
        .build()

    # Словарь соответствия Severity в MP SIEM и The HIVE
    severity_dict = {'Low': 1, 'Medium': 2, 'High': 3}

    case = Case(title=incident["name"],
                tlp=3,
                flag=True,
                tags=['MP SIEM', 'Script'],
                description='',
                severity=severity_dict[incident["severity"]],
                customFields=customFields)

    # Create the CASE
    response = api.create_case(case)

    if response.status_code == 201:
        # print(json.dumps(response.json(), indent=4, sort_keys=True))
        case_id = response.json()['id']
        print_log("INFO: New Case **" + incident["name"] + "** in The Hive created")
    else:
        print_log('ERROR: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)
    return case_id


def run():
    settings = read_config_file()
    # if settings['debug'] == 1:
    #     print(json.dumps(settings, indent=4, sort_keys=True))
    login_api(settings)
    api = TheHiveApi(str(settings['hive_url']), str(settings['hive_api_key']))

    sent_list = read_processed_file(settings['logfile'])
    incidents = get_incidents_list(settings)

    recv_list = []  # В массив будут заносится номера обработанных инцидентов

    for incident in (reversed(incidents["incidents"])):
        # Отсекаем INC- от инцидента и записываем в переменную только его номер
        inc_num = incident["key"].split('-')[-1]
        # if settings['debug'] == 1:
        #     print(json.dumps(incident, indent=4, sort_keys=True))
        if not sent_list or (int(sent_list[-1]) < int(inc_num)):
            recv_list.append(inc_num)
            events = get_inc_events(incident, settings)

            # Create the ALERT in Hive
            export_inc_to_alert(settings, api, incident, events, recv_list)

        else:
            print_log("INFO: Incident " + incident["key"] + " already have been imported")

    if settings['time_from'] != INC_PERIOD:
        update_time_from(0)


def edit_password():
    cipher_suite = Fernet(str.encode(KRAKOZYABRA))
    print("Please enter parameter [export_core_pass] (SIEM Core Password)")
    ecp = sys.stdin.readline()
    ecp_cipher = cipher_suite.encrypt(str.encode(ecp.strip()))
    print(ecp_cipher.decode())

    update_config(ecp_cipher.decode())


def update_config(ecp_cipher):
    settings = read_config_file()
    settings['export_core_pass'] = ecp_cipher

    with open(CONFIG, "w", encoding='utf-8') as fh:
        json.dump(settings, fh, indent=2)


def update_time_from(flag=1):
    settings = read_config_file()
    if flag == 0:
        settings['time_from'] = INC_PERIOD
    else:
        settings['time_from'] += INC_PERIOD//2

    with open(CONFIG, "w", encoding='utf-8') as fh:
        json.dump(settings, fh, indent=2, sort_keys=True)


def check_options():
    global CONFIG
    if len(sys.argv) == 1:
        return

    if sys.argv[1] == "-h":
        print("\n AVAILABLE OPTIONS:"
              "\n  -e : Edit SIEM Core password"
              "\n  -v : Script version"
              "\n  -h : Help")
        sys.exit(0)

    if sys.argv[1] == "-v":
        print("\n Version: %s" % VERSION)
        sys.exit(0)

    if sys.argv[1] == "-e":
        edit_password()
        sys.exit(0)


if __name__ == "__main__":
    start_time = time.time()
    check_options()
    run()
    print_log("--- Script execution time: %s seconds ---" % (time.time() - start_time))
