# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
# 	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Integration tests for the WAFv2 WebACL resource"""

import time
import pytest

from acktest.k8s import condition
from acktest.k8s import resource as k8s
from acktest.resources import random_suffix_name
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_wafv2_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e import web_acl

WEB_ACL_RESOURCE_PLURAL = "webacls"

CREATE_WAIT_SECONDS = 10
MODIFY_WAIT_SECONDS = 10
DELETE_WAIT_SECONDS = 10


@pytest.fixture(scope="module")
def simple_web_acl():
    web_acl_name = random_suffix_name("my-simple-web-acl", 24)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["WEB_ACL_NAME"] = web_acl_name

    resource_data = load_wafv2_resource(
        "web_acl_simple",
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP,
        CRD_VERSION,
        WEB_ACL_RESOURCE_PLURAL,
        web_acl_name,
        namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    yield (ref, cr)

    try:
        _, deleted = k8s.delete_custom_resource(ref, DELETE_WAIT_SECONDS)
        assert deleted
    except:
        pass


@service_marker
@pytest.mark.canary
class TestWebACL:
    def test_crud(self, simple_web_acl):
        ref, _ = simple_web_acl

        time.sleep(CREATE_WAIT_SECONDS)
        condition.assert_synced(ref)

        cr = k8s.get_resource(ref)

        assert "spec" in cr
        assert "name" in cr["spec"]
        web_acl_name = cr["spec"]["name"]

        assert "status" in cr
        assert "id" in cr["status"]
        web_acl_id = cr["status"]["id"]

        latest = web_acl.get(web_acl_name, web_acl_id)
        assert latest is not None
        assert "Rules" in latest
        assert "Description" in latest
        rules = latest["Rules"]
        description = latest["Description"]
        assert len(rules) == 2
        assert description == "initial description"

        # update the CR
        updates = {
            "spec": {
                "rules": [ADDITIONAL_RULE],
                "description": "updated description",
            },
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(MODIFY_WAIT_SECONDS)

        latest = web_acl.get(web_acl_name, web_acl_id)
        assert latest is not None
        assert "Rules" in latest
        assert "Description" in latest
        rules = latest["Rules"]
        description = latest["Description"]
        assert len(rules) == 1
        assert rules[0]["Name"] == "rule-3"
        assert description == "updated description"

        # delete the CR
        _, deleted = k8s.delete_custom_resource(ref, DELETE_WAIT_SECONDS)
        assert deleted
        web_acl.wait_until_deleted(web_acl_name, web_acl_id)


ADDITIONAL_RULE = {
    "name": "rule-3",
    "priority": 2,
    "action": {"block": {}},
    "visibilityConfig": {
        "metricName": "rule-3-metric",
        "sampledRequestsEnabled": True,
        "cloudWatchMetricsEnabled": True,
    },
    "statement": {
        "regexMatchStatement": {
            "regexString": "regex",
            "fieldToMatch": {
                "headers": {
                    "matchPattern": {"includedHeaders": ["User-Agent"]},
                    "matchScope": "KEY",
                    "oversizeHandling": "MATCH",
                }
            },
            "textTransformations": [{"type": "NONE", "priority": 0}],
        }
    },
}
