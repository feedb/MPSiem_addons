import requests
import re
import html
import csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime


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

    return session


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


if __name__ == "__main__":
    # Настройки
    settings = dict()

    # адрес сиема
    settings['base_url'] = ''
    # урл метода очистки списка
    settings['clear_method_url'] = '/api/events/v1/table_lists/blacklist/clear'
    # урл метода импорта данных
    settings['import_method_url'] = '/api/events/v1/table_lists/blacklist/import'
    # урл формы аутентификации
    settings['signin_form_url'] = '/account/login?returnUrl=/#/authorization/landing'
    # увл файла blacklist на github
    settings['blacklist_url'] = 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt'

    # логин
    settings['user'] = ''
    # пароль
    settings['pass'] = ''

    # Аутентификация
    session = authenticate(settings['base_url'], settings['user'], settings['pass'])

    if not external_auth(session, settings['base_url'] + settings['signin_form_url']):
        print("Ошибка аутентификация.")
    # аутентификация прошла
    else:
        # загружаем свежий blacklist
        resp = requests.get(settings['blacklist_url'], stream=True)

        # если всё хорошо
        if resp.status_code == 200:
            cur_date = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
            file_name = 'blacklist_' + cur_date + '.csv'

            # конвертируем в csv-файл
            with open(file_name, 'w', newline='') as csv_file:
                fieldnames = ['_last_changed', 'ip']
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=';', quoting=csv.QUOTE_ALL)
                writer.writeheader()

                for line in resp.iter_lines():
                    writer.writerow({
                        fieldnames[0]: cur_date,
                        fieldnames[1]: line.decode("utf-8")
                    })

            # очищаем старый список
            session.post(settings['base_url'] + settings['clear_method_url'])

            # загружаем новые данные
            with open(file_name, 'rb') as data:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                resp = session.post(settings['base_url'] + settings['import_method_url'], data=data, headers=headers)
                #print(resp.text)
        # ошибка аутентификации
        else:
            print("Не удалось импортировать новый blacklist.")
