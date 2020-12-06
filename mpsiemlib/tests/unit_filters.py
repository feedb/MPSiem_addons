import unittest

from mpsiemlib.common import *
from mpsiemlib.modules import MPSIEMWorker

from tests.settings import creds_ldap, settings


class FiltersTestCase(unittest.TestCase):
    __mpsiemworker = None
    __module = None
    __creds_ldap = creds_ldap
    __settings = settings

    def setUp(self) -> None:
        self.__mpsiemworker = MPSIEMWorker(self.__creds_ldap, self.__settings)
        self.__module = self.__mpsiemworker.get_module(ModuleNames.FILTERS)

    def tearDown(self) -> None:
        self.__module.close()

    def test_get_folders_list(self):
        folders = self.__module.get_folders_list()

        self.assertTrue(len(folders) != 0)

    def test_get_filters_list(self):
        filters = self.__module.get_filters_list()

        self.assertTrue(len(filters) != 0)

    def test_get_filter_info(self):
        filter_id = next(iter(self.__module.get_filters_list()))
        filter_info = self.__module.get_filter_info(filter_id)

        self.assertTrue(len(filter_info) != 0)


if __name__ == '__main__':
    unittest.main()
