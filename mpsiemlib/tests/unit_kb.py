import time
import unittest

from mpsiemlib.common import *
from mpsiemlib.modules import MPSIEMWorker

from tests.settings import creds_ldap, settings


class KBTestCase(unittest.TestCase):
    __mpsiemworker = None
    __module = None
    __creds_ldap = creds_ldap
    __settings = settings

    def __choose_any_db(self):
        dbs = self.__module.get_databases_list()
        db_name = None
        if "Editable" in dbs:
            db_name = "Editable"
        elif "dev" in dbs:
            db_name = "dev"
        else:
            db_name = next(iter(dbs))

        return db_name

    def __choose_deployable_db(self):
        db_name = None
        dbs = self.__module.get_databases_list()
        for k, v in dbs.items():
            if v.get("deployable"):
                db_name = k
                break

        return db_name

    def setUp(self) -> None:
        self.__mpsiemworker = MPSIEMWorker(self.__creds_ldap, self.__settings)
        self.__module = self.__mpsiemworker.get_module(ModuleNames.KB)

    def tearDown(self) -> None:
        self.__module.close()

    def test_get_databases_list(self):
        ret = self.__module.get_databases_list()
        self.assertTrue(len(ret) != 0)

    def test_get_groups_list(self):
        db_name = self.__choose_any_db()
        ret = self.__module.get_groups_list(db_name)
        self.assertTrue(len(ret) != 0)

    def test_get_folders_list(self):
        db_name = self.__choose_any_db()
        ret = self.__module.get_folders_list(db_name)
        self.assertTrue(len(ret) != 0)

    def test_get_packs_list(self):
        db_name = self.__choose_any_db()
        ret = self.__module.get_packs_list(db_name)
        self.assertTrue(ret is not None)

    def test_get_all_objects(self):
        db_name = self.__choose_any_db()
        norm = []
        for i in self.__module.get_normalizations_list(db_name):
            norm.append(i)
        corr = []
        for i in self.__module.get_correlations_list(db_name):
            corr.append(i)
        agg = []
        for i in self.__module.get_aggregations_list(db_name):
            agg.append(i)
        enrch = []
        for i in self.__module.get_enrichments_list(db_name):
            enrch.append(i)
        tbls = []
        for i in self.__module.get_tables_list(db_name):
            tbls.append(i)

        self.assertTrue((len(norm) != 0) and
                        (len(corr) != 0) and
                        (len(agg) != 0) and
                        (len(enrch) != 0) and
                        (len(tbls) != 0))

    def test_get_object_id_by_name(self):
        db_name = self.__choose_any_db()

        norm = next(self.__module.get_normalizations_list(db_name))
        object_name = norm.get("name")
        object_id = norm.get("id")

        calc_ids = self.__module.get_table_id_by_name(db_name, MPContentTypes.NORMALIZATION, object_name)

        found = False
        for i in calc_ids:
            if i.get("id") == object_id:
                found = True

        self.assertTrue(found)

    def test_get_rule(self):
        db_name = self.__choose_any_db()

        rule_info = next(self.__module.get_normalizations_list(db_name))
        rule_id = rule_info.get("id")
        norm_rule = self.__module.get_rule(db_name, MPContentTypes.NORMALIZATION, rule_id)

        rule_info = next(self.__module.get_correlations_list(db_name))
        rule_id = rule_info.get("id")
        corr_rule = self.__module.get_rule(db_name, MPContentTypes.CORRELATION, rule_id)

        rule_info = next(self.__module.get_aggregations_list(db_name))
        rule_id = rule_info.get("id")
        agg_rule = self.__module.get_rule(db_name, MPContentTypes.AGGREGATION, rule_id)

        rule_info = next(self.__module.get_enrichments_list(db_name))
        rule_id = rule_info.get("id")
        enrch_rule = self.__module.get_rule(db_name, MPContentTypes.ENRICHMENT, rule_id)

        self.assertTrue((len(norm_rule) != 0) and
                        (len(corr_rule) != 0) and
                        (len(agg_rule) != 0) and
                        (len(enrch_rule) != 0))

    def test_get_table_info(self):
        db_name = self.__choose_any_db()

        tbl = next(self.__module.get_tables_list(db_name))
        tbl_id = tbl.get("id")

        ret = self.__module.get_table_info(db_name, tbl_id)

        self.assertTrue(len(ret) != 0)

    def test_get_table_data(self):
        db_name = self.__choose_any_db()

        tbl = next(self.__module.get_tables_list(db_name))
        tbl_id = tbl.get("id")

        ret = self.__module.get_table_data(db_name, tbl_id)

        self.assertTrue(ret is not None)

    def test_deploy(self):
        db_name = self.__choose_deployable_db()

        norm_rule = None
        for i in self.__module.get_normalizations_list(db_name, filters={"filters": {"DeploymentStatus": ["1"]}}):
            if i.get("deployment_status") == "notinstalled":
                norm_rule = i
                break
        deploy_id = self.__module.install_objects(db_name, [norm_rule.get('id')])

        success_install = False
        for i in range(6):
            time.sleep(10)
            deploy_status = self.__module.get_deploy_status(db_name, deploy_id)
            if deploy_status.get("deployment_status") == "succeeded":
                success_install = True
                break

        deploy_id = self.__module.uninstall_object(db_name, [norm_rule.get('id')])

        success_uninstall = False
        for i in range(6):
            time.sleep(10)
            deploy_status = self.__module.get_deploy_status(db_name, deploy_id)
            if deploy_status.get("deployment_status") == "succeeded":
                success_uninstall = True
                break

        self.assertTrue(success_install and success_uninstall)

    def test_start_stop_rule(self):
        db_name = self.__choose_deployable_db()
        rule = next(self.__module.get_correlations_list(db_name, filters={"filters": {"DeploymentStatus": ["1"]}}))
        rule_id = rule.get("id")
        self.__module.stop_rule(db_name, MPContentTypes.CORRELATION, [rule_id])
        is_stopped = self.__module.get_rule_running_state(db_name,
                                                          MPContentTypes.CORRELATION,
                                                          rule_id).get("state") == "stopped"
        self.__module.start_rule(db_name, MPContentTypes.CORRELATION, [rule_id])
        is_running = self.__module.get_rule_running_state(db_name,
                                                          MPContentTypes.CORRELATION,
                                                          rule_id).get("state") == "running"

        self.assertTrue(is_stopped and is_running)


if __name__ == '__main__':
    unittest.main()
