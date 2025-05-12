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
import boto3

from acktest.k8s import condition
from acktest.k8s import resource as k8s
from acktest.resources import random_suffix_name
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_wafv2_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e import web_acl
from e2e.bootstrap_resources import get_bootstrap_resources

WEB_ACL_RESOURCE_PLURAL = "webacls"

CREATE_WAIT_SECONDS = 30
MODIFY_WAIT_SECONDS = 20
DELETE_WAIT_SECONDS = 20


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


@pytest.fixture(scope="module")
def nested_statement_web_acl():
    web_acl_name = random_suffix_name("my-nested-web-acl", 24)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["WEB_ACL_NAME"] = web_acl_name

    resource_data = load_wafv2_resource(
        "web_acl_nested_statement",
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


@pytest.fixture(scope="module")
def web_acl_with_logging():
    web_acl_name = random_suffix_name("webacl-logging", 24)
    
    # Get the bootstrap resources
    bootstrap_resources = get_bootstrap_resources()
    s3_bucket_arn = f"arn:aws:s3:::{bootstrap_resources.WAFLoggingBucket.name}"

    replacements = REPLACEMENT_VALUES.copy()
    replacements["WEB_ACL_NAME"] = web_acl_name
    replacements["S3_BUCKET_ARN"] = s3_bucket_arn

    resource_data = load_wafv2_resource(
        "web_acl_with_logging",
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
        # First delete the logging configuration
        wafv2_client = boto3.client("wafv2")
        if cr and "status" in cr and "ackResourceMetadata" in cr["status"] and "arn" in cr["status"]["ackResourceMetadata"]:
            try:
                wafv2_client.delete_logging_configuration(
                    ResourceArn=cr["status"]["ackResourceMetadata"]["arn"]
                )
            except:
                pass
                
        # Then delete the WebACL resource
        _, deleted = k8s.delete_custom_resource(ref, DELETE_WAIT_SECONDS)
        assert deleted
        if "spec" in cr and "name" in cr["spec"] and "status" in cr and "id" in cr["status"]:
            web_acl.wait_until_deleted(cr["spec"]["name"], cr["status"]["id"])
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

    def nested_statement(self, nested_statement_web_acl):
        ref, _ = nested_statement_web_acl

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
        rules = latest["Rules"]
        assert len(rules) == 1

        # check the nested statement
        assert "Statement" in rules[0]
        assert "AndStatement" in rules[0]["Statement"]
        statements = rules[0]["Statement"]["AndStatement"]["Statements"]
        assert len(statements) == 2
        assert "GeoMatchStatement" in statements[0]
        assert "NotStatement" in statements[1]
        assert "ByteMatchStatement" in statements[1]["NotStatement"]["Statement"]

        # delete the CR
        _, deleted = k8s.delete_custom_resource(ref, DELETE_WAIT_SECONDS)
        assert deleted
        web_acl.wait_until_deleted(web_acl_name, web_acl_id)

    def test_logging_configuration(self, web_acl_with_logging):
        ref, _ = web_acl_with_logging

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
        
        # Check logging configuration is present
        logging_config = None
        try:
            wafv2_client = boto3.client("wafv2")
            response = wafv2_client.get_logging_configuration(
                ResourceArn=cr["status"]["ackResourceMetadata"]["arn"]
            )
            logging_config = response.get("LoggingConfiguration")
        except:
            pass
        
        assert logging_config is not None
        assert "LogDestinationConfigs" in logging_config
        assert len(logging_config["LogDestinationConfigs"]) == 1
        
        assert "LogType" in logging_config
        assert logging_config["LogType"] == "WAF_LOGS"
        
        # Verify initial redacted fields
        assert "RedactedFields" in logging_config
        assert len(logging_config["RedactedFields"]) == 2
        redacted_fields = [
            field.get("SingleHeader", {}).get("Name")
            for field in logging_config["RedactedFields"]
            if "SingleHeader" in field
        ]
        assert "authorization" in redacted_fields
        assert "cookie" in redacted_fields
        
        # Update redacted fields (remove cookie and add user-agent)
        updates = {
            "spec": {
                "loggingConfiguration": {
                    "redactedFields": [
                        {"singleHeader": {"name": "authorization"}},
                        {"singleHeader": {"name": "user-agent"}}
                    ]
                }
            }
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(MODIFY_WAIT_SECONDS)
        
        # Check updated logging configuration
        try:
            response = wafv2_client.get_logging_configuration(
                ResourceArn=cr["status"]["ackResourceMetadata"]["arn"]
            )
            logging_config = response.get("LoggingConfiguration")
        except:
            pass
        
        assert logging_config is not None
        assert "RedactedFields" in logging_config
        assert len(logging_config["RedactedFields"]) == 2
        
        redacted_fields = [
            field.get("SingleHeader", {}).get("Name")
            for field in logging_config["RedactedFields"]
            if "SingleHeader" in field
        ]
        assert "authorization" in redacted_fields
        assert "user-agent" in redacted_fields
        assert "cookie" not in redacted_fields
        
        # Verify logging filter is still intact
        assert "LoggingFilter" in logging_config
        assert logging_config["LoggingFilter"]["DefaultBehavior"] == "KEEP"
        assert len(logging_config["LoggingFilter"]["Filters"]) == 1


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
