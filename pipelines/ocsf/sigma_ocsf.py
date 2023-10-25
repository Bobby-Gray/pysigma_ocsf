from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition, LogsourceCondition, RuleProcessingItemAppliedCondition, RuleProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import ChangeLogsourceTransformation, RuleFailureTransformation, DetectionItemFailureTransformation, FieldMappingTransformation
from sigma.rule import SigmaRule

def logsource_ocsf_cloud_aws() -> LogsourceCondition:
    return LogsourceCondition(
    product="aws",
    service="cloudtrail"
    )

def logsource_ocsf_cloud_gcp() -> LogsourceCondition:
    return LogsourceCondition(
    product="gcp",
    service="gcp.audit"
    )
    
class AggregateRuleProcessingCondition(RuleProcessingCondition):
    """"""
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join([item.lower() for item in rule.detection.condition])
        if any(f in condition_string for f in agg_function_strings):
            return True
        else:
            return False

def ocsf_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to OCSF Transformation",
        priority=10,
        items=[
            ProcessingItem(
                identifier="ocsf_cloud_aws_fieldmapping",
                transformation=FieldMappingTransformation({
                    "eventName": "api.operation",
                    "eventSource": "api.service.name"
                }),
                rule_conditions=[
                    logsource_ocsf_cloud_aws()
                ]
            ),
            ProcessingItem(
                identifier="ocsf_cloud_gcp_fieldmapping",
                transformation=FieldMappingTransformation({
                    "gcp.audit.method_name": "api.operation",
                    "eventSource": "api.service.name"
                }),
                rule_conditions=[
                    logsource_ocsf_cloud_gcp()
                ]
            ),
            # change logsource property
            ProcessingItem(
                identifier="ocsf_cloud_aws_logsource",
                transformation=ChangeLogsourceTransformation(
                    product="AWS",
                    service="Cloudtrail"
                ),
                rule_conditions=[
                    logsource_ocsf_cloud_aws(),
                ]
            ),
            # change logsource property
            ProcessingItem(
                identifier="ocsf_cloud_gcp_logsource",
                transformation=ChangeLogsourceTransformation(
                    product="GCP",
                    service="Cloud Audit Logs"
                ),
                rule_conditions=[
                    logsource_ocsf_cloud_gcp(),
                ]
            ),
            # Handle unsupported log sources - here we are checking whether none of the log source-specific transformations
            # that were set above have applied and throwing a RuleFailureTransformation error if this condition is met. Otherwise,
            # a separate processing item would be needed for every unsupported log source type
            ProcessingItem(
                identifier="ocsf_fail_rule_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation("Rule type not yet supported by OCSF Sigma backend!"),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("ocsf_cloud_aws_fieldmapping"),
                    RuleProcessingItemAppliedCondition("ocsf_cloud_aws_logsource"),
                    RuleProcessingItemAppliedCondition("ocsf_cloud_gcp_logsource")
                ],
            ),
            
            # Handle rules that use aggregate functions
            ProcessingItem(
                identifier="ocsf_fail_rule_conditions_not_supported",
                transformation=RuleFailureTransformation("Rules with aggregate function conditions like count, min, max, avg, sum, and near are not supported by the OCSF Sigma backend!"),
                rule_conditions=[
                    AggregateRuleProcessingCondition()
                ],
        )
    ]
)