from typing import Iterator, IO

from mpsiemlib.common import ModuleInterface, MPSIEMAuth, LoggingHandler, MPComponents, Settings
from mpsiemlib.common import exec_request, get_metrics_start_time, get_metrics_took_time


class Tables(ModuleInterface, LoggingHandler):
    """
    Tables module
    """

    __api_table_info = "/api/events/v2/table_lists/{}"
    __api_table_search = "/api/events/v2/table_lists/{}/content/search"
    __api_table_truncate = "/api/events/v2/table_lists/{}/content"
    __api_table_list = "/api/events/v2/table_lists"
    __api_table_import = "/api/events/v1/table_lists/{}/import"

    def __init__(self, auth: MPSIEMAuth, settings: Settings):
        ModuleInterface.__init__(self, auth, settings)
        LoggingHandler.__init__(self)
        self.__core_session = auth.connect(MPComponents.CORE)
        self.__core_hostname = auth.creds.core_hostname
        self.__tables_cache = {}
        self.log.debug('status=success, action=prepare, msg="Table Module init"')

    def get_tables_list(self) -> dict:
        """
        Получить список всех установленных табличных списков

        :return: {'id': 'name'}
        """
        self.log.debug('status=prepare, action=get_groups, msg="Try to get table list", '
                       'hostname="{}"'.format(self.__core_hostname))

        url = "https://{}{}".format(self.__core_hostname, self.__api_table_list)
        rq = exec_request(self.__core_session, url, method="GET", timeout=self.settings.connection_timeout)
        self.__tables_cache.clear()
        response = rq.json()
        for i in response:
            self.__tables_cache[i["name"]] = {"id": i.get("token"),
                                              "type": i.get("fillType").lower(),
                                              "editable": i.get("editable"),
                                              "ttl_enabled": i.get("ttlEnabled"),
                                              "notifications": i.get("notifications")}

        self.log.info('status=success, action=get_table_list, msg="Found {} tables", '
                      'hostname="{}"'.format(len(self.__tables_cache), self.__core_hostname))

        return self.__tables_cache

    def get_table_data(self, table_name: str, filters=None) -> Iterator[dict]:
        """
        Итеративно загружаем содержимое табличного списка

        Пример фильтра:
            filters = {"select": ["_last_changed", "field2", "field3"],
                   "where": "_id>5",
                   "orderBy": [{"field": "_last_changed",
                                "sortOrder": "descending"}],
                   "timeZone": 0}

        :param table_name: Имя таблицы
        :param filters: Фильтр, опционально
        :return: Итератор по строкам таблицы
        """
        api_url = self.__api_table_search.format(self.get_table_id_by_name(table_name))
        url = "https://{}{}".format(self.__core_hostname, api_url)
        params = {"filter": {"where": "",
                             "orderBy": [{"field": "_last_changed",
                                          "sortOrder": "descending"}],
                             "timeZone": 0}
                  }

        if filters is not None:
            params["filter"] = filters

        # Пачками выгружаем содержимое таблички
        is_end = False
        offset = 0
        limit = self.settings.tables_batch_size
        line_counter = 0
        start_time = get_metrics_start_time()
        while not is_end:
            ret = self.__iterate_table(url, params, offset, limit)
            if len(ret) < limit:
                is_end = True
            offset += limit
            for i in ret:
                line_counter += 1
                yield i
        took_time = get_metrics_took_time(start_time)

        self.log.info('status=success, action=get_table_data, msg="Query executed, response have been red", '
                      'hostname="{}", lines={}'.format(self.__core_hostname, line_counter))
        self.log.info('hostname="{}", metric=get_table_data, took={}ms, objects={}'.format(self.__core_hostname,
                                                                                           took_time,
                                                                                           line_counter))

    def __iterate_table(self, url, params, offset, limit):
        params["offset"] = offset
        params["limit"] = limit
        rq = exec_request(self.__core_session,
                          url,
                          method="POST",
                          timeout=self.settings.connection_timeout,
                          json=params)
        response = rq.json()
        if response is None or "items" not in response:
            self.log.error('status=failed, action=table_iterate, msg="Table data request return None or '
                           'has wrong response structure", '
                           'hostname="{}"'.format(self.__core_hostname))
            raise Exception("Table data request return None or has wrong response structure")

        return response.get("items")

    def set_table_data(self, table_name: str, data: IO) -> None:
        """
        Импортировать бинарные данные в табличный список.
        Данные должны быть в формате CSV, понятном MP SIEM.

        Usage:
            with open("import.csv", "rb") as data:
                Tables.set_data("table_name", data)

        :param table_name: Имя таблицы
        :param data: Поток бинарных данных для вставки
        :return: None
        """
        self.log.debug('status=prepare, action=get_groups, msg="Try to import data to {}", '
                       'hostname="{}"'.format(table_name, self.__core_hostname))

        api_url = self.__api_table_import.format(table_name)
        url = "https://{}{}".format(self.__core_hostname, api_url)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        rq = exec_request(self.__core_session,
                          url,
                          method="POST",
                          timeout=self.settings.connection_timeout,
                          data=data,
                          headers=headers)
        response = rq.json()

        total_records = response.get('recordsNum')
        imported_records = response.get('importedNum')
        bad_records = response.get('badRecordsNum')
        skipped_records = response.get('skippedRecordsNum')
        if (imported_records == 0 or imported_records <= bad_records + skipped_records) and total_records != 0:
            self.log.error('status=failed, action=set_table_data, msg="Importing data to table {} ends with error", '
                           'hostname="{}", total={}, imported={}, bad={}, skipped={}'.format(table_name,
                                                                                             self.__core_hostname,
                                                                                             total_records,
                                                                                             imported_records,
                                                                                             bad_records,
                                                                                             skipped_records))
            raise Exception("Importing data to table {} ends with error".format(table_name))

        if bad_records != 0 or skipped_records != 0:
            self.log.error('status=warning, action=set_table_data, msg="Some data not imported to table {}", '
                           'hostname="{}", total={}, imported={}, bad={}, skipped={}'.format(table_name,
                                                                                             self.__core_hostname,
                                                                                             total_records,
                                                                                             imported_records,
                                                                                             bad_records,
                                                                                             skipped_records))
        self.log.info('status=success, action=set_table_data, msg="Data imported to table {}", '
                      'hostname="{}", lines={}'.format(table_name, self.__core_hostname, imported_records))

    def get_table_info(self, table_name) -> dict:
        """
        Получить метаданные по табличке

        :param table_name: Имя таблицы
        :return: {'property': 'value'}
        """
        self.log.debug('status=prepare, action=get_groups, msg="Try to get table info for {}", '
                       'hostname="{}"'.format(table_name, self.__core_hostname))

        table_id = self.get_table_id_by_name(table_name)
        api_url = self.__api_table_info.format(table_id)
        url = "https://{}{}".format(self.__core_hostname, api_url)
        rq = exec_request(self.__core_session, url, method="GET", timeout=self.settings.connection_timeout)
        response = dict(rq.json())

        table_info = self.__tables_cache.get(table_name)
        table_info["size_max"] = response.get("maxSize")
        table_info["size_typical"] = response.get("typicalSize")
        table_info["ttl"] = response.get("ttl")
        table_info["description"] = response.get("description")
        table_info["created"] = response.get("created")
        table_info["updated"] = response.get("lastUpdated")
        table_info["size_current"] = response.get("currentSize")
        table_info["fields"] = response.get("fields")

        self.log.info('status=success, action=get_table_info, msg="Get {} properties for table {}", '
                      'hostname="{}"'.format(len(table_info), table_name, self.__core_hostname))

        return table_info

    def truncate_table(self, table_name: str) -> None:
        """
        Очистить табличный список

        :param table_name: Имя таблицы
        :return: None
        """
        self.log.debug('status=prepare, action=truncate_table, msg="Try to truncate table {}", '
                       'hostname="{}"'.format(table_name, self.__core_hostname))

        api_url = self.__api_table_truncate.format(self.get_table_id_by_name(table_name))
        url = "https://{}{}".format(self.__core_hostname, api_url)

        rq = exec_request(self.__core_session, url, method="DELETE", timeout=self.settings.connection_timeout)
        response = rq.json()

        if "result" not in response or response.get("result") != "success":
            self.log.error('status=failed, action=table_truncate, msg="Table {} have not been truncated", '
                           'hostname="{}"'.format(table_name, self.__core_hostname))
            raise Exception("Table {} have not been truncated".format(table_name))

        self.log.info('status=success, action=truncate_table, msg="Table {} have been truncated", '
                      'hostname="{}"'.format(table_name, self.__core_hostname))

    def get_table_id_by_name(self, table_name: str) -> str:
        if len(self.__tables_cache) == 0:
            self.get_tables_list()
        table_id = self.__tables_cache.get(table_name)
        if table_id is None:
            raise Exception("Table list {} not found in cache".format(table_name))
        return table_id.get("id")

    def close(self):
        if self.__core_session is not None:
            self.__core_session.close()
