from bs4 import BeautifulSoup
import json
from pprint import pprint
import requests
import sigma.data.mitre_attack as mitre
from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition, LogsourceCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import ChangeLogsourceTransformation, RuleFailureTransformation, DetectionItemFailureTransformation, FieldMappingTransformation
import yaml

class SigmOCSF:

    def logsource_ocsf_system_activity() -> LogsourceCondition:
        return LogsourceCondition(
        category="system_activity"
        )

    def logsource_ocsf_findings() -> LogsourceCondition:
        return LogsourceCondition(
        category="findings"
        )

    def logsource_ocsf_iam() -> LogsourceCondition:
        return LogsourceCondition(
        category="iam"
        )
    
    def logsource_ocsf_network() -> LogsourceCondition:
        return LogsourceCondition(
        category="network"
        )
    
    def logsource_ocsf_discovery() -> LogsourceCondition:
        return LogsourceCondition(
        category="discovery"
        )

    def logsource_ocsf_application() -> LogsourceCondition:
        return LogsourceCondition(
        category="application"
        )
    
    def ocsf_pipeline():
        return ProcessingPipeline(
            name="Generic Log Sources to OCSF Transformation",
            priority=10,
            items=[
                # Process Creation field mapping
                ProcessingItem(
                    identifier="ocsf_system_activity_fieldmapping",
                    transformation=FieldMappingTransformation({
                        "ProcessId": "process.pid",
                        "Image": "process.exe_path",
                        "FileVersion": "process.exe_file.version",
                        "Description": "process.exe_file.description",
                        "Product": "process.exe_file.product_name",
                        "Company": "process.exe_file.author",
                        "OriginalFileName": "process.name",
                        "CommandLine": "process.cmd_line",
                        "User": "process.username",
                        "ParentProcessId": "parent_process.pid",
                        "ParentImage": "parent_process.exe_path",
                        "ParentCommandLine": "parent_process.cmd_line",
                        "ParentUser": "parent_process.username",
                        "md5": "process.exe_file.hashes.md5",
                        "sha1": "process.exe_file.hashes.sha1",
                        "sha256": "process.exe_file.hashes.sha256"
                    }),
                    rule_conditions=[
                        logsource_ocsf_system_activity(),
                    ]
                ),
                # Handle unsupported Process Start fields
                ProcessingItem(
                    identifier="insight_idr_fail_process_start_fields",
                    transformation=DetectionItemFailureTransformation("The InsightIDR backend does not support the CurrentDirectory, IntegrityLevel, or imphash fields for process start rules."),
                    rule_conditions=[
                        logsource_ocsf_system_activity()
                    ],
                    detection_item_conditions=[
                        IncludeFieldCondition(
                            fields=[
                                "CurrentDirectory",
                                "IntegrityLevel",
                                "imphash",
                                "LogonId"
                            ]
                        )
                    ]
                ),
                # Change logsource properties
                ProcessingItem(
                    identifier="insight_idr_process_start_logsource",
                    transformation=ChangeLogsourceTransformation(
                        category="process_start_event",
                        product="windows"
                    ),
                    rule_conditions=[
                        logsource_ocsf_system_activity(),
                    ],
                )
            ]
        )

    # def logsource_generic_dns_query() -> LogsourceCondition:
    #     return LogsourceCondition(
    #     category="dns"
    #     )

    # def logsource_web_proxy() -> LogsourceCondition:
    #     return LogsourceCondition(
    #         category="proxy"
    #     )

    # def logsource_firewall() -> LogsourceCondition:
    #     return LogsourceCondition(
    #         category="firewall"
    #     )


    # def insight_idr_pipeline():
    #     

sigmocsf = SigmOCSF()

get_ocsf_categories = sigmocsf.logsource_ocsf_system_activity()

if __name__=="__main__":
    pprint(f'ran: {sigmocsf}')