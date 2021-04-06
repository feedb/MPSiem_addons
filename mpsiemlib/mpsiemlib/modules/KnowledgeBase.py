import os
import yaml

from hashlib import sha256
from typing import Iterator, Optional
from tempfile import TemporaryDirectory

from mpsiemlib.common import ModuleInterface, MPSIEMAuth, LoggingHandler, MPComponents, Settings, MPContentTypes
from mpsiemlib.common import exec_request, get_metrics_start_time, get_metrics_took_time
from mpsiemlib.helpers import ContentPack, content_folder_to_work_copy, work_copy_to_content_folder


class KnowledgeBase(ModuleInterface, LoggingHandler):
    """
    PT KB module
    """

    __kb_port = 8091

    #  обрабатывается в KB
    __api_root = '/api-studio'
    __api_kb_db_list = f'{__api_root}/content-database-selector/content-databases'
    __api_temp_file_storage_upload = f'{__api_root}/tempFileStorage/upload'

    __api_siem = f'{__api_root}/siem'
    __api_deploy_object = f'{__api_siem}/deploy'
    __api_deploy_log = f'{__api_siem}/deploy/log'
    __api_list_objects = f'{__api_siem}/objects/list'
    __api_rule_code = f'{__api_siem}' + '/{}-rules/{}'
    __api_table_info = f'{__api_siem}' + '/tabular-lists/{}'
    __api_table_rows = f'{__api_siem}' + '/tabular-lists/{}/rows'
    __api_groups = f'{__api_siem}/groups'
    __api_folders_packs_list = f'{__api_siem}/folders/tree?includeObjects=true'
    __api_folders = f'{__api_siem}/folders'
    __api_co_rules = f'{__api_siem}/correlation-rules'
    __api_export = f'{__api_siem}/export'
    __api_import = f'{__api_siem}/import'
    __api_mass_operations = f'{__api_siem}/mass-operations'
    __api_siem_objgroups_values = f'{__api_mass_operations}/SiemObjectGroup/values'

    # обрабатывается в Core
    __api_rule_running_info = "/api/siem/v2/rules/{}/{}"
    __api_rule_stop = "/api/siem/v2/rules/{}/commands/stop"
    __api_rule_start = "/api/siem/v2/rules/{}/commands/start"

    # Форматы экспорта
    EXPORT_FORMAT_KB = 'kb'
    EXPORT_FORMAT_SIEM_LITE = 'siem'

    # Режимы импорта

    # Добавить и обновить объекты из файла
    #
    # Все объекты из файла добавятся как пользовательские.
    # Существующие в системе объекты будут заменены, в том числе
    # записи табличных списков.
    IMPORT_ADD_AND_UPDATE = 'upsert'

    # Добавить объекты Локальная система как системные
    #
    # Будут импортированы только объекты Локальная система.
    # Новые объекты добавятся, существующие будут заменены.
    IMPORT_LOCAL_SYSTEM_AS_SYSTEM = 'upsert_origin'

    # Синхронизировать объекты Локальная система с содержимым файла
    #
    # Будут импортированы только объекты Локальная система.
    # Существующие объекты будут заменены на объекты из файла,
    # а объекты, которых нет в файле, будут удалены из системы.
    IMPORT_SYNC_SYSTEM = 'replace_origin'

    def __init__(self, auth: MPSIEMAuth, settings: Settings):
        ModuleInterface.__init__(self, auth, settings)
        LoggingHandler.__init__(self)
        self.__kb_session = auth.connect(MPComponents.KB)
        self.__kb_hostname = auth.creds.core_hostname
        self.__rules_mapping = {}
        self.__groups = {}
        self.__folders = {}
        self.__packs = {}
        self.log.debug('status=success, action=prepare, msg="KB Module init"')

    def install_objects(self, db_name: str, guids_list: list, do_remove=False) -> str:
        """
        Установить объекты из KB в SIEM

        :param db_name: Имя БД
        :param guids_list: Список обЪектов для установки
        :param do_remove:
        :return: deploy ID
        """
        self.log.info('status=prepare, action=install_objects, msg="Try to install {} objects {}", '
                      'hostname="{}", db="{}"'.format("install" if not do_remove else "uninstall",
                                                      guids_list,
                                                      self.__kb_hostname,
                                                      db_name))
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        params = {"mode": "selection" if not do_remove else "uninstall",
                  "include": guids_list}
        url = "https://{}:{}{}".format(self.__kb_hostname,
                                       self.__kb_port,
                                       self.__api_deploy_object)
        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)
        response = r.json()

        self.log.info('status=success, action=install_objects, msg="{} objects {}", '
                      'hostname="{}", db="{}"'.format("Install" if not do_remove else "Uninstall",
                                                      guids_list,
                                                      self.__kb_hostname,
                                                      db_name))

        return response.get("Id")

    def install_objects_by_group_id(self, db_name: str, group_id: str) -> str:
        """
        Установить объекты из KB в SIEM

        :param db_name: Имя БД
        :param group_id: ID набора для установки, None для установки всего контента
        :return: deploy ID
        """
        self.log.info('status=prepare, action=install_objects_by_group_id, msg="Try to install group {}", '
                      'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))

        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        if group_id is None:
            params = {"mode": "all"}
        else:
            params = {"mode": "group", "groupId": group_id}
        url = "https://{}:{}{}".format(self.__kb_hostname,
                                       self.__kb_port,
                                       self.__api_deploy_object)
        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)
        response = r.json()

        self.log.info('status=success, action=install_objects_by_group_id, msg="Install group {}", '
                      'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))

        return response.get("Id")

    def uninstall_object(self, db_name: str, guids_list: list) -> str:
        """
        Удалить объекты из SIEM

        :param db_name: Имя БД
        :param guids_list: Список обЪектов для удаления из SIEM
        :return: deploy ID
        """

        return self.install_objects(db_name, guids_list, do_remove=True)

    def get_deploy_status(self, db_name: str, deploy_id: str) -> dict:
        """
        Получить общий статус установки контента

        :param db_name: Имя БД
        :param deploy_id: Идентификатор процесса установки/удаления
        :return: {"start_date": "date_string", "deployment_status": "succeeded|running"}
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        params = {"skip": 0, "take": 100, "deployStatusIds": []}
        url = "https://{}:{}{}".format(self.__kb_hostname,
                                       self.__kb_port,
                                       self.__api_deploy_log)
        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)
        state = r.json()

        ret = {}
        for i in state:
            if i.get("Id") != deploy_id:
                continue
            ret = {"start_date": i.get("StartDate"),
                   "deployment_status": i.get("DeployStatusId")}
        self.log.info('status=success, action=get_deploy_status, msg="Got deploy status", '
                      'hostname="{}", db="{}", status="{}"'.format(self.__kb_hostname, db_name, ret))
        return ret

    def start_rule(self, db_name: str, content_type: str, guids_list: list):
        """
        Запустить правила, установленные в SIEM Server
        Используются ID правил из KB.
        
        :param db_name: Имя БД в KB
        :param content_type: MPContentType
        :param guids_list: Список ID правил для установки
        :return: 
        """
        self.__manipulate_rule(db_name, content_type, guids_list, "start")

    def stop_rule(self, db_name: str, content_type: str, guids_list: list):
        """
        Остановить правило, установленное в SIEM Server
        Используются ID правил из KB.
        
        :param db_name: Имя БД в KB
        :param content_type: MPContentType
        :param guids_list: Список ID правил для установки
        :return: 
        """
        self.__manipulate_rule(db_name, content_type, guids_list, "stop")

    def __manipulate_rule(self, db_name: str, content_type: str, guids_list: list, control="stop"):
        # нет гарантий, что объекты в PT KB и SIEM будут называться одинаково.
        # сейчас в классе прописаны названия из PT KB. Название табличек уже разное.
        object_type = None
        if content_type == MPContentTypes.CORRELATION:
            object_type = "correlation"
        elif content_type == MPContentTypes.ENRICHMENT:
            object_type = "enrichment"
        else:
            raise Exception("Unsupported content type to stop {}".format(content_type))

        if len(self.__rules_mapping) == 0:
            self.__update_rules_mapping(db_name, content_type)

        rules_names = []
        for i in guids_list:
            name = self.__rules_mapping.get(db_name, {}).get(content_type, {}).get(i, {}).get("name")
            if name is None:
                self.log.error('status=failed, action=manipulate_rule, msg="Rule id not found", '
                               'hostname="{}", db="{}", rule_id="{}"'.format(self.__kb_hostname, db_name, i))
            rules_names.append(name)

        data = {"names": rules_names}
        api_url = self.__api_rule_start.format(object_type) if control == "start" \
            else self.__api_rule_stop.format(object_type)
        url = "https://{}{}".format(self.__kb_hostname, api_url)
        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         json=data)
        response = r.json()

        if len(response.get("error")) != 0:
            self.log.error('status=failed, action=manipulate_rule, '
                           'msg="Got error while manipulate rule", hostname="{}", rules_ids="{}", '
                           'rules_names="{}", db="{}", error="{}"'.format(self.__kb_hostname,
                                                                          guids_list,
                                                                          rules_names,
                                                                          db_name,
                                                                          response.get("error")))
            raise Exception("Got error while manipulate rule")

        self.log.info('status=success, action=manipulate_rule, msg="{} {} rules", '
                      'hostname="{}", rules_names="{}", db="{}"'.format(control,
                                                                        object_type,
                                                                        self.__kb_hostname,
                                                                        rules_names,
                                                                        db_name))

    def get_rule_running_state(self, db_name: str, content_type: str, guid: str):
        """
        Получить статус правила, работающего в SIEM Server.
        Используются ID правил из KB.
        
        :param db_name: Имя БД в KB
        :param content_type: MPContentType
        :param guid: ID правила
        :return: 
        """
        object_type = None
        if content_type == MPContentTypes.CORRELATION:
            object_type = "correlation"
        elif content_type == MPContentTypes.ENRICHMENT:
            object_type = "enrichment"
        else:
            raise Exception("Unsupported content type to stop {}".format(content_type))

        if len(self.__rules_mapping) == 0:
            self.__update_rules_mapping(db_name, content_type)

        name = self.__rules_mapping.get(db_name, {}).get(content_type, {}).get(guid, {}).get("name")

        api_url = self.__api_rule_running_info.format(object_type, name)
        url = "https://{}{}".format(self.__kb_hostname, api_url)
        r = exec_request(self.__kb_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        response = r.json()

        state = response.get("state", {})

        return {"state": state.get("name"), "reason": state.get("reason"), "context": state.get("context")}

    def get_databases_list(self) -> dict:
        """
        Получить список БД

        :return: {'db_name': {'param1': 'value1'}}
        """
        # TODO Не учитывается что БД с разными родительскими БД могут иметь одинаковое имя
        url = "https://{}:{}{}".format(self.__kb_hostname,
                                       self.__kb_port,
                                       self.__api_kb_db_list)
        r = exec_request(self.__kb_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout)
        db_names = r.json()
        ret = {}
        for i in db_names:
            name = i.get("Name")
            ret[name] = {"id": i.get("Uid"),
                         "status": i.get("Status").lower(),
                         "updatable": i.get("IsUpdatable"),
                         "deployable": i.get("IsDeployable"),
                         "parent": i.get("ParentName"),
                         "revisions": i.get("RevisionsCount")}

        self.log.info('status=success, action=get_databases_list, msg="Got {} databases", '
                      'hostname="{}"'.format(len(ret), self.__kb_hostname))

        return ret

    def get_groups_list(self, db_name: str, do_refresh=False) -> dict:
        """
        Получить список групп

        :param db_name: Имя БД
        :param do_refresh: Обновить кэш
        :return: {'group_id': {'parent_id': 'value', 'name': 'value'}}
        """
        if not do_refresh and len(self.__groups) != 0:
            return self.__groups

        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, self.__api_groups)

        r = exec_request(self.__kb_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout,
                         headers=headers)
        groups = r.json()
        self.__groups.clear()

        for i in groups:
            self.__groups[i.get("Id")] = {"parent_id": i.get("ParentGroupId"),
                                          "name": i.get("SystemName")}

        self.log.info('status=success, action=get_groups_list, msg="Got {} groups", '
                      'hostname="{}", db="{}"'.format(len(self.__groups), self.__kb_hostname, db_name))

        return self.__groups

    def get_folders_list(self, db_name: str, do_refresh=False) -> dict:
        """
        Получить список папок

        :param db_name: Имя БД
        :param do_refresh: Обновить кэш
        :return: {'group_id': {'parent_id': 'value', 'name': 'value'}}
        """
        if not do_refresh and len(self.__folders) == 0:
            self.__iterate_folders_tree(db_name)

        self.log.info('status=success, action=get_folders_list, msg="Got {} folders", '
                      'hostname="{}", db="{}"'.format(len(self.__folders), self.__kb_hostname, db_name))

        return self.__folders

    def get_packs_list(self, db_name: str, do_refresh=False) -> dict:
        """
        Получить список паков

        :param db_name: Имя БД
        :param do_refresh: Обновить кэш
        :return: {'group_id': {'parent_id': 'value', 'name': 'value'}}
        """
        if not do_refresh and len(self.__packs) != 0:
            self.__iterate_folders_tree(db_name)

        self.log.info('status=success, action=get_packs_list, msg="Got {} packs", '
                      'hostname="{}", db="{}"'.format(len(self.__packs), self.__kb_hostname, db_name))

        return self.__packs

    def __iterate_folders_tree(self, db_name: str):
        params = {"expandNodes": []}
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, self.__api_folders_packs_list)

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)
        folders_packs = r.json()
        self.__folders.clear()
        self.__packs.clear()

        for i in folders_packs:
            node_type = i.get("NodeKind")
            current = None
            if node_type == "Folder":
                current = self.__folders
            elif node_type == "KnowledgePack":
                current = self.__packs
            else:
                continue

            current[i.get("Id")] = {"parent_id": i.get("ParentId"),
                                    "name": i.get("Name")}

    def get_normalizations_list(self, db_name: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Получить список правил нормализации

        :param db_name: Имя БД
        :param filters: см get_all_objects
        :return: Iterator
        """
        params = {"filters": {"SiemObjectType": ["Normalization"]}}
        if filters is not None:
            filters.update(params)
        else:
            filters = params

        return self.get_all_objects(db_name, filters)

    def get_correlations_list(self, db_name: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Получить список правил корреляции

        :param db_name: Имя БД
        :param filters: см get_all_objects
        :return: Iterator
        """
        params = {"filters": {"SiemObjectType": ["Correlation"]}}
        if filters is not None:
            filters.update(params)
        else:
            filters = params

        return self.get_all_objects(db_name, filters)

    def get_enrichments_list(self, db_name: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Получить список правил обогащения

        :param db_name: Имя БД
        :param filters: см get_all_objects
        :return: Iterator
        """
        params = {"filters": {"SiemObjectType": ["Enrichment"]}}
        if filters is not None:
            filters.update(params)
        else:
            filters = params

        return self.get_all_objects(db_name, filters)

    def get_aggregations_list(self, db_name: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Получить список правил агрегации

        :param db_name: Имя БД
        :param filters: см get_all_objects
        :return: Iterator
        """
        params = {"filters": {"SiemObjectType": ["Aggregation"]}}
        if filters is not None:
            filters.update(params)
        else:
            filters = params

        return self.get_all_objects(db_name, filters)

    def get_tables_list(self, db_name: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Получить список табличек

        :param db_name: Имя БД
        :param filters: см get_all_objects
        :return: Iterator
        """
        params = {"filters": {"SiemObjectType": ["TabularList"]}}
        if filters is not None:
            filters.update(params)
        else:
            filters = params

        return self.get_all_objects(db_name, filters)

    def get_all_objects(self, db_name: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Выгрузка всех объектов, кроме макросов

        :param db_name: Имя БД из которой идет выгрузка
        :param filters: {"folderId": null,
                        "filters": {
                            "SiemObjectType": ["Normalization"],
                            "ContentType": ["System"],
                            "DeploymentStatus": ["0"],
                            "CompilationStatus": ["2"],
                            "SiemObjectRegex": [".*_test_name"]
                        },
                        "search": "",
                        "sort": [{"name": "objectId", "order": 0, "type": 1}],
                        "groupId": null,
                    }
        :return: {"param1": "value1", "param2": "value2"}
        """
        self.log.info('status=prepare, action=get_all_objects, msg="Try to get objects list", '
                      'hostname="{}", db="{}", filters="{}"'.format(self.__kb_hostname, db_name, filters))

        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, self.__api_list_objects)
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        params = {
            'sort': [{'name': "objectId", 'order': 0, 'type': 1}],
        }
        if filters is not None:
            params.update(filters)

        # Пачками выгружаем содержимое
        is_end = False
        offset = 0
        limit = self.settings.kb_objects_batch_size
        line_counter = 0
        start_time = get_metrics_start_time()
        while not is_end:
            ret = self.__iterate_objects(url, params, headers, offset, limit)
            if len(ret) < limit:
                is_end = True
            offset += limit
            for i in ret:
                line_counter += 1
                yield {"id": i.get("Id"),
                       "guid": i.get("ObjectId"),
                       "name": i.get("SystemName"),
                       "folder_id": i.get("FolderId"),
                       "object_kind": i.get("ObjectKind"),
                       "folder_path": i.get("FolderPath").replace('\\','/') if i.get("FolderPath") else "",
                       "origin_id": i.get("OriginId"),
                       "compilation_sdk": i.get("CompilationStatus", {}).get("SdkVersion"),
                       "compilation_status": i.get("CompilationStatus", {}).get("CompilationStatusId"),
                       "deployment_status": i.get("DeploymentStatus", '').lower()}
        took_time = get_metrics_took_time(start_time)

        self.log.info('status=success, action=get_all_objects, msg="Query executed, response have been read", '
                      'hostname="{}", filter="{}", lines={}, db="{}"'.format(self.__kb_hostname,
                                                                             filters,
                                                                             line_counter,
                                                                             db_name))
        self.log.info('hostname="{}", metric=get_all_objects, took={}ms, objects={}'.format(self.__kb_hostname,
                                                                                            took_time,
                                                                                            line_counter))

    def __iterate_objects(self, url: str, params: dict, headers: dict, offset: int, limit: int):
        params["withoutGroups"] = False
        params["recursive"] = True
        params["skip"] = offset
        params["take"] = limit
        rq = exec_request(self.__kb_session,
                          url,
                          method="POST",
                          timeout=self.settings.connection_timeout,
                          headers=headers,
                          json=params)
        response = rq.json()
        if response is None or "Rows" not in response:
            self.log.error('status=failed, action=kb_objects_iterate, msg="KB data request return None or '
                           'has wrong response structure", '
                           'hostname="{}"'.format(self.__kb_hostname))
            raise Exception("KB data request return None or has wrong response structure")

        return response.get("Rows")

    def get_id_by_name(self, db_name: str, content_type: str, object_name: str) -> list:
        """
        Узнать ID объекта по его имени.
        KB позволяет создавать объекты с неуникальным именем.

        :param db_name: Имя БД
        :param content_type: Тип объекта MPContentType
        :param object_name: Имя искомого объекта
        :return: [{'id': value, 'folder_id': value}]
        """
        if len(self.__rules_mapping) == 0:
            self.__update_rules_mapping(db_name, content_type)

        ret = []
        for k, v in self.__rules_mapping[db_name][content_type].items():
            if v.get("name") == object_name:
                ret.append({"id": k, "folder_id": v.get("folder_id"), "guid": v.get("guid")})
        return ret

    def __update_rules_mapping(self, db_name: str, content_type: str):
        if self.__rules_mapping.get(db_name) is None:
            self.__rules_mapping[db_name] = {}
        if self.__rules_mapping.get(db_name).get(content_type) is None:
            self.__rules_mapping[db_name][content_type] = {}
        params = {"filters": {"SiemObjectType": [content_type]}}
        for i in self.get_all_objects(db_name, params):
            self.__rules_mapping[db_name][content_type][i.get("id")] = {"name": i.get("name"),
                                                                        "folder_id": i.get("folder_id"),
                                                                        "guid": i.get("guid")}

    def get_rule(self, db_name: str, content_type: str, rule_id: str) -> dict:
        """
        Получить полное описание и тело правила.

        :param db_name: Имя БД
        :param content_type: Тип объекта MPContentType
        :param rule_id: KB ID правила
        :return: {'param1': value, 'param2': value}
        """
        if content_type == MPContentTypes.TABLE:
            raise Exception('Method get_rule not supported {}'.format(MPContentTypes.TABLE))

        self.log.info('status=success, action=get_rule, msg="Try to get rule {}", '
                      'hostname="{}", db="{}"'.format(rule_id, self.__kb_hostname, db_name))

        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        api_url = self.__api_rule_code.format(content_type.lower(), rule_id)
        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, api_url)

        r = exec_request(self.__kb_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout,
                         headers=headers)
        rule = r.json()

        rule_groups = []
        for i in rule.get("Groups"):
            rule_groups.append({"id": i.get("Id"), "name": i.get("SystemName")})

        ret = {"id": rule.get("Id"),
               "guid": rule.get("ObjectId"),
               "folder_id": rule.get("Folder", {}).get("Id"),
               "origin_id": rule.get("OriginId"),
               "name": rule.get("SystemName"),
               "formula": rule.get("Formula"),
               "groups": rule_groups,
               "localization_rules": rule.get("LocalizationRules"),
               "compilation_sdk": rule.get("CompilationStatus", {}).get("SdkVersion"),
               "compilation_status": rule.get("CompilationStatus", {}).get("CompilationStatusId"),
               "deployment_status": rule.get("DeploymentStatus", '').lower()}
        ret["hash"] = sha256(str(ret.get("formula", '')).encode("utf-8")).hexdigest()

        self.log.info('status=success, action=get_rule, msg="Got rule {}", '
                      'hostname="{}", db="{}"'.format(rule_id, self.__kb_hostname, db_name))

        return ret

    def get_table_info(self, db_name: str, table_id: str) -> dict:
        """
        Получить описание табличного списка.

        :param db_name: Имя БД
        :param table_id: KB ID табличного списка
        :return: {'param1': value, 'param2': value}
        """

        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        api_url = self.__api_table_info.format(table_id)
        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, api_url)

        r = exec_request(self.__kb_session,
                         url,
                         method='GET',
                         timeout=self.settings.connection_timeout,
                         headers=headers)
        table = r.json()

        table_groups = []
        for i in table.get("Groups"):
            table_groups.append({"id": i.get("Id"), "name": i.get("SystemName")})

        table_fields = []
        for i in table.get("Fields"):
            table_fields.append({"name": i.get("Name"),
                                 "mapping": i.get("Mapping"),
                                 "type_id": i.get("TypeId"),
                                 "primary_key": i.get("IsPrimaryKey"),
                                 "indexed": i.get("IsIndex"),
                                 "nullable": i.get("IsNullable")})

        ret = {"id": table.get("Id"),
               "guid": table.get("ObjectId"),
               "folder_id": table.get("Folder").get("Id") if table.get("Folder") is not None else None,
               "origin_id": table.get("OriginId"),
               "name": table.get("SystemName"),
               "size_max": table.get("MaxSize"),
               "size_typical": table.get("TypicalSize"),
               "ttl": table.get("Ttl"),
               "fields": table_fields,
               "description": table.get("Description"),
               "groups": table_groups,
               "fill_type": table.get("FillType").lower(),
               "pdql": table.get("PdqlQuery"),
               "asset_groups": table.get("AssetGroups"),
               "deployment_status": table.get("DeploymentStatus").lower()}

        self.log.info('status=success, action=get_table_info, msg="Got table {}", '
                      'hostname="{}", db="{}"'.format(table_id, self.__kb_hostname, db_name))

        return ret

    def get_table_data(self, db_name: str, table_id: str, filters: Optional[dict] = None) -> Iterator[dict]:
        """
        Получить содержимое табличного из KB.
        В KB только справочники могут содержать записи.
        Для доступа к данным иных типов таблиц необходимо использовать class Table

        :param db_name: Имя БД
        :param table_id: KB ID табличного списка
        :param filters: KB фильтр записей в таблице. Спецификацию можно найти путем реверса WEB API
        :return: Iterator
        """
        api_url = self.__api_table_rows.format(table_id)

        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, api_url)
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        params = {'sort': None}

        if filters is not None:
            params.update(filters)

        # Пачками выгружаем содержимое
        is_end = False
        offset = 0
        limit = self.settings.kb_objects_batch_size
        line_counter = 0
        start_time = get_metrics_start_time()
        while not is_end:
            ret = self.__iterate_table_rows(url, params, headers, offset, limit)
            if len(ret) < limit:
                is_end = True
            offset += limit
            for i in ret:
                line_counter += 1
                i.pop("Id")
                yield i
        took_time = get_metrics_took_time(start_time)

        self.log.info('status=success, action=get_table_data, msg="Query executed, response have been read", '
                      'hostname="{}", lines={}, db="{}"'.format(self.__kb_hostname, line_counter, db_name))
        self.log.info('hostname="{}", metric=get_table_data, took={}ms, lines={}'.format(self.__kb_hostname,
                                                                                         took_time,
                                                                                         line_counter))

    def __iterate_table_rows(self, url: str, params: dict, headers: dict, offset: int, limit: int):
        params["skip"] = offset
        params["take"] = limit
        rq = exec_request(self.__kb_session,
                          url,
                          method="POST",
                          timeout=self.settings.connection_timeout,
                          headers=headers,
                          json=params)
        response = rq.json()
        if response is None or "Rows" not in response:
            self.log.error('status=failed, action=kb_objects_iterate, msg="KB data request return None or '
                           'has wrong response structure", '
                           'hostname="{}"'.format(self.__kb_hostname))
            raise Exception("KB data request return None or has wrong response structure")

        return response.get("Rows")

    def create_folder(self, db_name: str, name: str, parent_id: Optional[str] = None) -> str:
        """
        Создать папку для контента

        :param db_name: Имя БД
        :param name: Имя создаваемой папки
        :param parent_id: Идентификатор родительской папки
        :return: ID созданной папки
        """
        params = {
            "name": name,
            "parentId": parent_id
        }
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{hostname}:{port}{endpoint}".format(hostname=self.__kb_hostname,
                                                           port=self.__kb_port,
                                                           endpoint=self.__api_folders)

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)

        if r.status_code == 201:
            self.log.info('status=success, action=create_folder, msg="created folder {} with id {}", '
                          'hostname="{}", db="{}"'.format(name, r.json(), self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=create_folder, msg="failed to create folder {}", '
                           'hostname="{}", db="{}"'.format(name, self.__kb_hostname, db_name))

        return r.json()

    def delete_folder(self, db_name: str, folder_id: str):
        """
        Удалить папку

        :param db_name: Имя БД
        :param folder_id: ID удаляемой папки
        :return: Объект Response
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{hostname}:{port}{endpoint}/{folderId}".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_folders,
            folderId=folder_id
        )

        r = exec_request(self.__kb_session,
                         url,
                         method='DELETE',
                         timeout=self.settings.connection_timeout,
                         headers=headers)

        if r.status_code == 204:
            self.log.info('status=success, action=delete_folder, msg="deleted folder {}", '
                          'hostname="{}", db="{}"'.format(folder_id, self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=delete_folder, msg="failed to delete folder {}", '
                           'hostname="{}", db="{}"'.format(folder_id, self.__kb_hostname, db_name))

        return r

    def create_co_rule(self, db_name: str, name: str, code: str, ru_desc: Optional[str],
                       folder_id: str, group_ids: Optional[list] = []) -> str:
        """
        Создать правило корреляции

        :param db_name: Имя БД
        :param name: имя создаваемого правила корреляции
        :param code: код правила
        :param ru_desc: описание в русской локали
        :param folder_id: ID каталога, в который разместить правило
        :param group_ids: ID наборов установки, в которые включить правило
        :return: ID созданного правила
        """
        params = {
            "systemName": name,
            "formula": code,
            "description": {},
            "folderId": folder_id,
            "groupsToSave": group_ids,
            "localizationRulesToAdd": [],
            "mappingConflictAction": "exception"
        }

        if ru_desc:
            params.update({
                "description": {
                    "RUS": ru_desc
                }
            })

        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{hostname}:{port}{endpoint}".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_co_rules
        )

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)

        if r.status_code == 201:
            self.log.info('status=success, action=create_co_rule, msg="created co rule {} with id {}", '
                          'hostname="{}", db="{}"'.format(name, r.json(), self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=create_co_rule, msg="failed to create co rule {}", '
                           'hostname="{}", db="{}"'.format(name, self.__kb_hostname, db_name))

        return r.json()

    def delete_co_rule(self, db_name: str, rule_id: str):
        """
        Удалить правило корреляции

        :param db_name: Имя БД
        :param rule_id: ID правила
        :return: Объект Response
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{hostname}:{port}{endpoint}/{ruleId}".format(hostname=self.__kb_hostname,
                                                                    port=self.__kb_port,
                                                                    endpoint=self.__api_co_rules,
                                                                    ruleId=rule_id)

        r = exec_request(self.__kb_session,
                         url,
                         method='DELETE',
                         timeout=self.settings.connection_timeout,
                         headers=headers)

        if r.status_code == 204:
            self.log.info('status=success, action=delete_co_rule, msg="deleted co rule {}", '
                          'hostname="{}", db="{}"'.format(rule_id, self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=delete_co_rule, msg="failed to delete co rule {}", '
                           'hostname="{}", db="{}"'.format(rule_id, self.__kb_hostname, db_name))

        return r

    def create_group(self, db_name: str, name: str, parent_id: Optional[str] = None) -> str:
        """
        Создать набор установки

        :param db_name: Имя БД
        :param name: Имя набора установки
        :param parent_id: ID родительского набора установки
        :return: ID созданного набора установки
        """
        params = {
            "systemName": name,
            "parentGroupId": parent_id,
            "locales": []
        }

        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{hostname}:{port}{endpoint}".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_groups
        )

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)

        if r.status_code == 201:
            self.log.info('status=success, action=create_group, msg="created group {} with id {}", '
                          'hostname="{}", db="{}"'.format(name, r.json(), self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=create_group, msg="failed to create group {}", '
                           'hostname="{}", db="{}"'.format(name, self.__kb_hostname, db_name))

        return r.json()

    def delete_group(self, db_name: str, group_id: str):
        """
        Удалить набор установки

        :param db_name: Имя БД
        :param group_id: ID удаляемого набора установки
        :return: Объект Response
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}

        params = {"MappingConflictAction": "exception"}

        url = "https://{hostname}:{port}{endpoint}/{ruleId}".format(hostname=self.__kb_hostname,
                                                                    port=self.__kb_port,
                                                                    endpoint=self.__api_groups,
                                                                    ruleId=group_id)

        r = exec_request(self.__kb_session,
                         url,
                         method='DELETE',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)

        if r.status_code == 204:
            self.log.info('status=success, action=delete_group, msg="deleted group {}", '
                          'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=delete_group, msg="failed to delete group {}", '
                           'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))

        return r

    def is_group_empty(self, db_name: str, group_id: str) -> bool:
        """
        Проверить есть ли данные в наборе установки

        :param db_name: имя БД
        :param group_id: идентификатор набора установки
        :return: True - если в наборе установки нет контента
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}

        params = { "skip" : 0,
                   "folderId" : None,
                   "filters" : None,
                   "search":"",
                   "sort":[
                       {"name":"objectId","order":0,"type":0}
                   ],
                   "recursive" : True,
                   "groupId":group_id,
                   "withoutGroups" : False,
                   "take":50
                   }

        url = "https://{hostname}:{port}{endpoint}".format(hostname=self.__kb_hostname,
                                                                    port=self.__kb_port,
                                                                    endpoint=self.__api_list_objects
                                                                    )

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)

        if r.status_code == 201:

            num_rows = r.json().get('Count', 0)

            self.log.info('status=success, action=list_group, msg="group {} has {} rows", '
                          'hostname="{}", db="{}"'.format(group_id, num_rows, self.__kb_hostname, db_name))

            return True if num_rows == 0 else False

        else:
            self.log.error('status=failed, action=list_group, msg="failed to list group {}", '
                           'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))

    def get_group_path_by_id(self, db_name: str, folder_id: str) -> str:
        """
        Получить путь в дереве наборов установки по идентификатору набора установки

        :param db_name: Имя БД
        :param folder_id: идентификатор набора установки
        :return: путь в дереве наборов установки вида root/child/grandchild
        """
        if not self.__groups:
            groups = self.get_groups_list(db_name)
        else:
            groups = self.__groups
        parent = groups[folder_id]['parent_id']
        name = groups[folder_id]['name']
        ret_path = self.get_group_path_by_id(db_name, parent) if parent else ''
        return '/'.join((ret_path, name)) if ret_path else name

    def get_group_id_by_path(self, db_name: str, search_path: str) -> str:
        """
        Получить идентификатор набора установки по пути в дереве

        :param db_name: Имя БД
        :param path: Путь в формате root/child/grandchild
        :return: идентификатор набора установки
        """
        groups = self.get_groups_list(db_name)
        path_index = {}
        for current_id, group_data in groups.items():
            path = self.get_group_path_by_id(db_name, current_id)
            path_index[path] = current_id

        return path_index.get(search_path, '')

    def __get_group_children_tree(self, groups, current_id) -> list:
        children = groups[current_id]['children_ids'] if 'children_ids' in groups[current_id] else []
        retval = list(children)
        for child in children:
            grand_children = self.__get_group_children_tree(groups, child)
            retval.extend(grand_children)

        return retval

    def get_nested_group_ids(self, db_name: str, group_id: str) -> list:
        """
        Получить идентификаторы дочерних наборов установки

        :param db_name: Имя БД
        :param group_id: идентификатор группы
        :return: список идентификаторов дочерних наборов установки
        """
        groups = dict(self.get_groups_list(db_name))
        for current_id, group_data in groups.items():
            parent_id = group_data['parent_id']
            if parent_id:
                if 'children_ids' not in groups[parent_id]:
                    groups[parent_id]['children_ids'] = []

                groups[parent_id]['children_ids'].append(current_id)

        return self.__get_group_children_tree(groups, group_id)

    def export_group(self, db_name: str, group_id: str, local_filepath: str,
                     export_format: Optional[str] = EXPORT_FORMAT_KB,
                     metadata_filepath: str = '',
                     group_relative_root: str = '') -> int:
        """
        Экспортировать набор установки

        :param db_name: имя БД
        :param group_id: ID набора установки
        :param local_filepath: файл в который сохранить набор установки
        :param export_format: формат экспорта (KB / SIEM Lite)
        :metadata_filepath: имя файла для сохранения метаданных (по умолчанию не сохраняются).
                            В метаданных сохраняется путь для экспорта
        :metadata_relative_root: путь, который считать корневым при экспорте дерева наборов установки
        :return: размер созданного файла
        """

        headers = {'Content-Locale': 'RUS'}

        params = {
            "format": export_format,
            "groupId": group_id,
            "mode": "group"
        }

        url = "https://{hostname}:{port}{endpoint}/?contentDatabase={db_name}".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_export,
            db_name=db_name
        )

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params)

        retval = 0
        if r.status_code == 201:

            # Не экспортировать пустой пак (в него попадают все ПТшные макросы)
            is_group_empty = self.is_group_empty(db_name, group_id)
            if not is_group_empty:
                with open(local_filepath, 'wb') as kbfile:
                    retval = kbfile.write(r.content)

            self.log.info('status=success, action=export_group, msg="group {} exported", '
                          'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))

            if metadata_filepath:
                # Формирование метаданных

                absolute_path = self.get_group_path_by_id(db_name, group_id)
                if absolute_path.startswith(group_relative_root):
                    relative_path = os.path.relpath(absolute_path, group_relative_root).replace(os.sep, '/')
                else:
                    relative_path = absolute_path

                metadata = {
                    'group_path': relative_path,
                }

                # Добавить ссылки на контент в метаданные
                if not is_group_empty:
                    pack = ContentPack(local_filepath)
                    metadata['kb_tree'] = pack.get_content_links()

                with open(metadata_filepath, 'wt', encoding='utf-8') as meta_file:
                    yaml.safe_dump(
                        metadata,
                        meta_file,
                        allow_unicode = True
                    )
        else:
            self.log.error('status=failed, action=export_group, msg="failed to export group {}", '
                           'hostname="{}", db="{}"'.format(group_id, self.__kb_hostname, db_name))

        return retval

    def export_groups(self, db_name: str, group_paths: list, folder: str,
                      recursive: bool = True,
                      export_metadata: bool = True,
                      group_relative_root: str = ''
                      ):
        """
        Выгрузить наборы установки с метаданными

        :param db_name: Имя БД
        :param group_paths: Список путей в дереве наборов установки
        :param folder: Каталог для выгрузки
        :param recursive: Выгружать дочерние элементы дерева наборов установки
        :param export_metadata: Выгружать метаданные по набору установки
        :param group_relative_root: Узел в дереве наборов установки, который будет считаться корневым
        :return:
        """
        SPECIAL_CHARS = ['<', '>', ':', '"', '*', '|', '?']

        for group_path in group_paths:
            group_id_current = self.get_group_id_by_path(db_name, group_path)
            group_ids_total = [group_id_current, ]
            if recursive:
                group_ids_total.extend(self.get_nested_group_ids(db_name, group_id_current))

            for group_id in group_ids_total:
                group_path = self.get_group_path_by_id(db_name, group_id)

                if group_path.startswith(group_relative_root):
                    group_path = os.path.relpath(group_path, group_relative_root).replace(os.sep, '/')

                filename = '_'.join(group_path.split('/'))
                pack_filename = filename + '.kb'
                for char in SPECIAL_CHARS:
                    pack_filename = pack_filename.replace(char, '_')

                if export_metadata:
                    meta_filename = filename + '.yaml'
                    for char in SPECIAL_CHARS:
                        meta_filename= meta_filename.replace(char, '_')
                    metadata_filepath = os.path.join(folder, meta_filename)
                else:
                    metadata_filepath = ''

                self.export_group(db_name,
                                  group_id,
                                  os.path.join(folder, pack_filename),
                                  metadata_filepath=metadata_filepath,
                                  group_relative_root=group_relative_root
                                  )


    def export_groups_unpacked(self, db_name: str, group_paths: list, folder: str,
                      recursive: bool = True,
                      export_metadata: bool = True,
                      group_relative_root: str = ''):
        """
        Экспорт наборов установки в структуру рабочей копии

        :param db_name: имя БД
        :param group_paths: пути для экспорта
        :param folder: каталог рабочей копии
        :param recursive: выгружать дерево наборов устновки
        :param export_metadata: экспортировать метаданные по наборам установки
        :param group_relative_root: относительный путь в дереве наборов установки
        :return:
        """

        if not os.path.isdir(folder):
            os.mkdir(folder)

        with TemporaryDirectory() as tmp_dir:
            self.export_groups(db_name, group_paths, tmp_dir, recursive, export_metadata, group_relative_root)
            content_folder_to_work_copy(tmp_dir, folder)



    def import_group(self, db_name: str, filepath: str, mode: Optional[str] = IMPORT_ADD_AND_UPDATE) -> int:
        """
        Импортировать набор установки

        :param db_name: имя БД
        :param filepath: имя файла набора установки
        :param mode: режим импорта
        :return: response_code
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS',
                   'Content-Type': 'application/octet-stream'}


        filename = os.path.basename(filepath)

        url = "https://{hostname}:{port}{endpoint}?fileName={filename}&storageType=Temp".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_temp_file_storage_upload,
            filename=filename
        )

        uploaded_id = ""
        with open(filepath, 'rb') as kbfile:

            r = exec_request(self.__kb_session,
                             url,
                             method='POST',
                             timeout=self.settings.connection_timeout,
                             headers=headers,
                             data=kbfile,
                             )

            if r.status_code == 201:
                # Upload successful
                uploaded_id = r.json().get('UploadId')
                self.log.info('status=success, action=upload_file, msg="file {} uploaded", '
                              'hostname="{}", db="{}"'.format(filepath, self.__kb_hostname, db_name))
            else:
                self.log.error('status=failed, action=upload_file, msg="failed to upload file {}", '
                               'hostname="{}", db="{}"'.format(filepath, self.__kb_hostname, db_name))

        if uploaded_id:
            # make import

            headers = {'Content-Database': db_name,
                       'Content-Locale': 'RUS'}

            params = {
                "importMacros": False,
                "mode": mode,
                "uploadId": uploaded_id
            }

            url = "https://{hostname}:{port}{endpoint}".format(
                hostname=self.__kb_hostname,
                port=self.__kb_port,
                endpoint=self.__api_import
            )

            r = exec_request(self.__kb_session,
                             url,
                             method='POST',
                             timeout=self.settings.connection_timeout,
                             headers=headers,
                             json=params,
                             )

            if r.status_code == 201:
                # Upload successful
                self.log.info('status=success, action=import_file, msg="file {} imported", '
                              'hostname="{}", db="{}"'.format(filepath, self.__kb_hostname, db_name))
            else:
                self.log.error('status=failed, action=import_file, msg="failed to import file {}", '
                               'hostname="{}", db="{}"'.format(filepath, self.__kb_hostname, db_name))

            return r.status_code
        else:
            return -1

    def create_group_path(self, db_name: str, group_path: str) -> str:
        """
        Последовательное создание пути в дереве наборов установки

        :param db_name: Имя БД
        :param group_path: путь в дереве наборов установки
        :return: идентификатор листьевого набора установки
        """
        path_parts = group_path.split('/')
        for i in range(1, len(path_parts)+1):
            parent_path = '/'.join(path_parts[0:i-1])
            path = '/'.join(path_parts[0:i])
            group_id = self.get_group_id_by_path(db_name, path)
            if not group_id:
                parent_group_id = self.get_group_id_by_path(db_name, parent_path) or None
                self.create_group(db_name, path_parts[i-1], parent_group_id)

        return self.get_group_id_by_path(db_name, group_path)

    def __get_linked_ids(self, objects):
        """
        Разбор ответа на запрос привязанных наборов установки

        :param objects: ответ API MPSIEM
        :return:
        """
        linked = []
        for item in objects:
            if 'AssignedTo' in item and item['AssignedTo'] == 'All':
                if 'Id' in item:
                    linked.append(item['Id'])
            if 'Children' in item and item['Children']:
                linked.extend(self.__get_linked_ids(item['Children']))

        return linked

    def get_linked_groups(self, db_name: str, content_item_id: str) -> list:
        """
        Получить список идентификаторов связанных наборов установки для элемента контента

        :param db_name: Имя БД
        :param content_item_id: идентификатор контента
        :return: список идентификаторов связанных наборов установки
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}

        params = {
                    "include":[content_item_id, ],
                    "filter": None
        }

        url = "https://{hostname}:{port}{endpoint}".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_siem_objgroups_values
        )

        r = exec_request(self.__kb_session,
                         url,
                         method='POST',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params,
                         )

        if r.status_code == 201:

            group_ids = self.__get_linked_ids(r.json())

            self.log.info('status=success, action=get_linked_groups, msg="Item {} linked to groups {}", '
                          'hostname="{}", db="{}"'.format(content_item_id, group_ids, self.__kb_hostname, db_name))

            return group_ids
        else:
            self.log.error('status=failed, action=get_linked_groups, msg="can not get group links for {}", '
                           'hostname="{}", db="{}"'.format(content_item_id, self.__kb_hostname, db_name))

    def link_content_to_groups(self, db_name: str, content_items_ids: list, group_ids: list):
        """
        Связать идентификаторы контента с идентификаторами наборов установки

        :param db_name: Имя БД
        :param content_items_ids: идентификаторы контента
        :param group_ids: идентификаторы наборов устновки
        :return:
        """
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}

        params = {
            "Operations":[
                {
                    "Id":"SiemObjectGroup",
                    "ValuesToSave": group_ids,
                    "ValuesToRemove":[]
                }
            ],
            "Entities":{
                "include": content_items_ids,
                "filter":{}
            }
        }

        url = "https://{hostname}:{port}{endpoint}".format(
            hostname=self.__kb_hostname,
            port=self.__kb_port,
            endpoint=self.__api_mass_operations
        )

        r = exec_request(self.__kb_session,
                         url,
                         method='PUT',
                         timeout=self.settings.connection_timeout,
                         headers=headers,
                         json=params,
                         )

        if r.status_code == 200:
            self.log.info('status=success, action=link_content_to_groups, msg="{} linked to {}", '
                          'hostname="{}", db="{}"'.format(content_items_ids, group_ids, self.__kb_hostname, db_name))
        else:
            self.log.error('status=failed, action=import_file, msg="can not link {} to {}", '
                           'hostname="{}", db="{}"'.format(content_items_ids, group_ids, self.__kb_hostname, db_name))

    def __process_kb_metadata(self, db_name, obj_map, kb_meta):
        if 'group_path' in kb_meta and kb_meta['group_path']:
            # Создать путь в дереве наборов установки
            group_id = self.create_group_path(db_name, kb_meta['group_path'])

            # Есть связанные элементы контента
            if 'kb_tree' in kb_meta and kb_meta['kb_tree']:
                contend_guid_strs = []
                for content_type in kb_meta['kb_tree']:
                    for content_path in kb_meta['kb_tree'][content_type]:
                        key = (content_type, content_path)

                        # Пробуем найти маппинт (Type, Path)->GUID
                        if key in obj_map:
                            contend_guid_strs.append(obj_map[key])
                        else:
                            self.log.error('status=failed, action=map_id_to_guid, msg="can not find object {}", '
                                           'hostname="{}", db="{}"'.format(key, self.__kb_hostname,
                                                                           db_name))

                if contend_guid_strs:
                    # Связать контент с набором установки
                    self.link_content_to_groups(db_name, contend_guid_strs, [group_id, ])


    def import_groups(self, db_name: str, folder: str,
                                                create_groups: bool = True,
                                                group_relative_root: str = ''):
        """
        Импорт всех наборов установки из каталога
        Опиционально: восстановка дерева наборово установки

        :param db_name: Имя БД
        :param folder: Каталог с файлами для импорта
                        *.kb - наборы установки
                        *.yaml - метаданные по наборам установки
        :param create_groups: Создавать иерархию наборов установки
        :param group_relative_root: Набор установки под которым импортировать иерархию наборов установки
        :return:
        """

        if os.path.exists(folder):
            # Импортировать все наборы установки (*.kb)
            for filename in os.listdir(folder):
                if filename.endswith('.kb'):
                    self.import_group(db_name, os.path.join(folder, filename))

            # Создать иерархию наборов установки на основе метаданных (*.yaml)
            if create_groups:
                obj_map = {
                            (item['object_kind'], '/'.join((item['folder_path'], item['name']))): item['id']
                                                                            for item in self.get_all_objects(db_name)
                }

                for filename in os.listdir(folder):
                    if filename.endswith('.yaml'):
                        with open(os.path.join(folder, filename), 'rt', encoding='utf-8') as kb_meta_file:
                            self.__process_kb_metadata(db_name, obj_map, yaml.full_load(kb_meta_file))

    def import_groups_unpacked(self, db_name: str, folder: str,
                                                create_groups: bool = True,
                                                group_relative_root: str = ''):
        """
        Импорт групп из рабочей копии

        :param db_name: имя БД
        :param folder: каталог с рабочей копией
        :param create_groups: создавать наборы установки в SIEM
        :param group_relative_root: относительный путь под которым создавать наборы установки
        :return:
        """
        if os.path.isdir(folder):
            with TemporaryDirectory() as tmp_dir:
                work_copy_to_content_folder(folder, tmp_dir)
                print(os.listdir(tmp_dir))
                self.import_groups(db_name, tmp_dir, create_groups, group_relative_root)


    def close(self):
        if self.__kb_session is not None:
            self.__kb_session.close()
