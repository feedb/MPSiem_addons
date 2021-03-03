from hashlib import sha256
from typing import Iterator, Optional

from mpsiemlib.common import ModuleInterface, MPSIEMAuth, LoggingHandler, MPComponents, Settings, MPContentTypes
from mpsiemlib.common import exec_request, get_metrics_start_time, get_metrics_took_time


class KnowledgeBase(ModuleInterface, LoggingHandler):
    """
    PT KB module
    """

    __kb_port = 8091

    #  обрабатывается в KB
    __api_deploy_object = '/api-studio/siem/deploy'
    __api_deploy_log = '/api-studio/siem/deploy/log'
    __api_list_objects = '/api-studio/siem/objects/list'
    __api_kb_db_list = '/api-studio/content-database-selector/content-databases'
    __api_rule_code = '/api-studio/siem/{}-rules/{}'
    __api_table_info = '/api-studio/siem/tabular-lists/{}'
    __api_table_rows = '/api-studio/siem/tabular-lists/{}/rows'
    __api_groups_list = '/api-studio/siem/groups'
    __api_folders_packs_list = '/api-studio/siem/folders/tree?includeObjects=true'

    # обрабатывается в Core
    __api_rule_running_info = "/api/siem/v2/rules/{}/{}"
    __api_rule_stop = "/api/siem/v2/rules/{}/commands/stop"
    __api_rule_start = "/api/siem/v2/rules/{}/commands/start"

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
        self.log.info('status=prepare, action=install_objects, msg="Try to {} objects {}", '
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

    def get_groups_list(self, db_name: str) -> dict:
        """
        Получить список групп

        :param db_name: Имя БД
        :return: {'group_id': {'parent_id': 'value', 'name': 'value'}}
        """
        if len(self.__groups) != 0:
            return self.__groups
        headers = {'Content-Database': db_name,
                   'Content-Locale': 'RUS'}
        url = "https://{}:{}{}".format(self.__kb_hostname, self.__kb_port, self.__api_groups_list)

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

    def get_folders_list(self, db_name: str) -> dict:
        """
        Получить список папок

        :param db_name: Имя БД
        :return: {'group_id': {'parent_id': 'value', 'name': 'value'}}
        """
        if len(self.__folders) == 0:
            self.__iterate_folders_tree(db_name)

        self.log.info('status=success, action=get_folders_list, msg="Got {} folders", '
                      'hostname="{}", db="{}"'.format(len(self.__folders), self.__kb_hostname, db_name))

        return self.__folders

    def get_packs_list(self, db_name: str) -> dict:
        """
        Получить список паков

        :param db_name: Имя БД
        :return: {'group_id': {'parent_id': 'value', 'name': 'value'}}
        """
        if len(self.__packs) != 0:
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

    def close(self):
        if self.__kb_session is not None:
            self.__kb_session.close()
