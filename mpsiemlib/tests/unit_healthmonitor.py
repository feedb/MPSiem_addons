import unittest

from mpsiemlib.common import *
from mpsiemlib.modules import MPSIEMWorker

from tests.settings import creds_ldap, settings


class KBTestCase(unittest.TestCase):
    __mpsiemworker = None
    __module = None
    __creds_ldap = creds_ldap
    __settings = settings

    def setUp(self) -> None:
        self.__mpsiemworker = MPSIEMWorker(self.__creds_ldap, self.__settings)
        self.__module = self.__mpsiemworker.get_module(ModuleNames.HEALTH)

    def tearDown(self) -> None:
        self.__module.close()

    def test_get_global_status(self):
        ret = self.__module.get_health_status()
        self.assertTrue(type(ret) == str)

    def test_get_errors(self):
        ret = self.__module.get_health_errors()
        self.assertTrue(type(ret) == list)

    def test_get_license_status(self):
        ret = self.__module.get_health_license_status()
        self.assertTrue(len(ret) != 0)

    def test_get_agents_status(self):
        ret = self.__module.get_health_agents_status()
        self.assertTrue(len(ret) != 0)

    def test_get_kb_status(self):
        ret = self.__module.get_health_kb_status()
        self.assertTrue(len(ret) != 0)


if __name__ == '__main__':
    unittest.main()
