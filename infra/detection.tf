data "aws_iam_policy_document" "audit_bucket" {
  count = var.create_cloudtrail ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit[0].arn, "${aws_s3_bucket.audit[0].arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }

    condition {
      test     = "Bool"
      variable = "aws:PrincipalIsAWSService"
      values   = ["false"]
    }
  }

  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit[0].arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit[0].arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  count  = var.create_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id
  policy = data.aws_iam_policy_document.audit_bucket[0].json

  depends_on = [
    aws_s3_bucket_ownership_controls.private,
    aws_s3_bucket_public_access_block.audit,
    aws_s3_bucket_server_side_encryption_configuration.audit,
  ]
}

resource "aws_cloudtrail" "lab" {
  count                         = var.create_cloudtrail ? 1 : 0
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.audit[0].id
  kms_key_id                    = aws_kms_key.lab.arn
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = false
  is_multi_region_trail         = false

  event_selector {
    include_management_events = true
    read_write_type           = "WriteOnly"
  }

  depends_on = [aws_s3_bucket_policy.audit]
}

resource "aws_guardduty_detector" "lab" {
  count                        = var.create_guardduty_detector ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3" {
  count       = var.create_guardduty_detector ? 1 : 0
  detector_id = aws_guardduty_detector.lab[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = local.rule_names.cloudtrail
  description = "Alteracoes bem-sucedidas no bloqueio de acesso publico do bucket do lab."

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    account       = [local.account_id]
    region        = [local.region]
    detail = {
      eventSource        = ["s3.amazonaws.com"]
      eventName          = local.rules.cloudtrail_operations
      errorCode          = [{ exists = false }]
      recipientAccountId = [local.account_id]
      awsRegion          = [local.region]
      requestParameters = {
        bucketName = [aws_s3_bucket.lab.id]
      }
    }
  })
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = local.rule_names.guardduty
  description = "Achados selecionados de exfiltracao ou exclusao anomala no S3."

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    account       = [local.account_id]
    region        = [local.region]
    detail = {
      accountId = [local.account_id]
      region    = [local.region]
      type      = local.rules.guardduty_types
      severity  = [{ numeric = [">=", local.rules.guardduty_min_severity] }]
      service   = { archived = [false] }
    }
  })
}

resource "aws_cloudwatch_event_rule" "reconciliation" {
  name                = local.rule_names.reconciliation
  description         = "Releitura periodica do bloqueio de acesso publico no bucket do lab."
  schedule_expression = "rate(5 minutes)"
}

locals {
  event_rules = {
    cloudtrail     = aws_cloudwatch_event_rule.cloudtrail
    guardduty      = aws_cloudwatch_event_rule.guardduty
    reconciliation = aws_cloudwatch_event_rule.reconciliation
  }
}

resource "aws_cloudwatch_event_target" "queue" {
  for_each  = local.event_rules
  rule      = each.value.name
  target_id = "incident-queue"
  arn       = aws_sqs_queue.events.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 12
  }

  dead_letter_config {
    arn = aws_sqs_queue.delivery_dlq.arn
  }

  depends_on = [aws_sqs_queue_policy.queues]
}
