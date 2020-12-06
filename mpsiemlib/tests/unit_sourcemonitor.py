import pytz
import unittest

from datetime import datetime

from mpsiemlib.common import *
from mpsiemlib.modules import MPSIEMWorker

from tests.settings import creds_ldap, settings


class SourceMonitorTestCase(unittest.TestCase):
    __mpsiemworker = None
    __module = None
    __creds_ldap = creds_ldap
    __settings = settings
    __begin = None
    __end = None

    def setUp(self) -> None:
        self.__mpsiemworker = MPSIEMWorker(self.__creds_ldap, self.__settings)
        self.__module = self.__mpsiemworker.get_module(ModuleNames.SOURCE_MONITOR)
        self.__end = round(datetime.now(tz=pytz.timezone(settings.local_timezone)).timestamp())
        self.__begin = self.__end - 86400

    def tearDown(self) -> None:
        self.__module.close()

    def test_get_sources_list(self):
        ret = []
        for i in self.__module.get_sources_list(self.__begin, self.__end):
            ret.append(i)
        self.assertTrue(len(ret) != 0)

    def test_get_forwarders_list(self):
        ret = []
        for i in self.__module.get_forwarders_list(self.__begin, self.__end):
            ret.append(i)
        self.assertTrue(len(ret) != 0)

    def test_get_sources_by_forwarder(self):
        forwarder = next(self.__module.get_forwarders_list(self.__begin, self.__end))
        ret = []
        for i in self.__module.get_sources_by_forwarder(forwarder.get("id"), self.__begin, self.__end):
            ret.append(i)
        self.assertTrue(len(ret) != 0)


if __name__ == '__main__':
    unittest.main()
