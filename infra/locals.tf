locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  name       = var.project_name
  region     = var.aws_region
  rules      = jsondecode(file("${path.module}/../src/sentinela/rules.json"))

  trail_name = "${local.name}-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
  topic_arn  = "arn:${local.partition}:sns:${local.region}:${local.account_id}:${local.name}-alerts"

  rule_names = {
    cloudtrail     = "${local.name}-s3-bpa"
    guardduty      = "${local.name}-guardduty"
    reconciliation = "${local.name}-reconcile"
  }

  queue_names = {
    events     = "${local.name}-events"
    delivery   = "${local.name}-delivery-dlq"
    processing = "${local.name}-processing-dlq"
  }
  queue_arns = {
    for kind, name in local.queue_names : kind => "arn:${local.partition}:sqs:${local.region}:${local.account_id}:${name}"
  }

  alarm_names = {
    backlog    = "${local.name}-queue-backlog"
    delivery   = "${local.name}-delivery-dlq"
    processing = "${local.name}-processing-dlq"
  }
  alarm_arns = [
    for name in values(local.alarm_names) : "arn:${local.partition}:cloudwatch:${local.region}:${local.account_id}:alarm:${name}"
  ]

  worker_timeout = 30
}
