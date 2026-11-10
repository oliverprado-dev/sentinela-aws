data "aws_iam_policy_document" "lab_key" {
  statement {
    sid       = "EnableAccountIAM"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "EventBridgeQueueDelivery"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sqs:arn"
      values   = [local.queue_arns.events, local.queue_arns.delivery]
    }
  }

  statement {
    sid       = "CloudWatchAlarmPublish"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = local.alarm_arns
    }
  }

  dynamic "statement" {
    for_each = var.create_cloudtrail ? [1] : []
    content {
      sid       = "CloudTrailEncrypt"
      actions   = ["kms:GenerateDataKey*"]
      resources = ["*"]

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
        variable = "kms:EncryptionContext:aws:cloudtrail:arn"
        values   = [local.trail_arn]
      }
    }
  }

  dynamic "statement" {
    for_each = var.create_cloudtrail ? [1] : []
    content {
      sid       = "CloudTrailDescribeKey"
      actions   = ["kms:DescribeKey"]
      resources = ["*"]

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
  }
}

resource "aws_kms_key" "lab" {
  description             = "Criptografia S3, SQS, SNS e CloudTrail do laboratorio Sentinela AWS"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.lab_key.json
}

resource "aws_kms_alias" "lab" {
  name          = "alias/${local.name}-lab"
  target_key_id = aws_kms_key.lab.key_id
}

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = aws_kms_key.lab.arn
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "AllowLabAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = local.alarm_arns
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = nonsensitive(var.alert_email != null) ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  alarm_queues = {
    backlog = {
      queue       = aws_sqs_queue.events.name
      metric      = "ApproximateAgeOfOldestMessage"
      threshold   = 300
      description = "Mensagem pendente na fila principal por pelo menos cinco minutos."
    }
    delivery = {
      queue       = aws_sqs_queue.delivery_dlq.name
      metric      = "ApproximateNumberOfMessagesVisible"
      threshold   = 1
      description = "EventBridge nao conseguiu entregar pelo menos um evento."
    }
    processing = {
      queue       = aws_sqs_queue.processing_dlq.name
      metric      = "ApproximateNumberOfMessagesVisible"
      threshold   = 1
      description = "O worker esgotou as tentativas de pelo menos uma mensagem."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "queues" {
  for_each            = local.alarm_queues
  alarm_name          = local.alarm_names[each.key]
  alarm_description   = each.value.description
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.metric
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = each.value.queue }
  alarm_actions       = [aws_sns_topic.alerts.arn]

  depends_on = [aws_sns_topic_policy.alerts]
}
