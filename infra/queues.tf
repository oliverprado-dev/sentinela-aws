resource "aws_sqs_queue" "processing_dlq" {
  name                      = local.queue_names.processing
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.lab.arn
}

resource "aws_sqs_queue" "delivery_dlq" {
  name                      = local.queue_names.delivery
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.lab.arn
}

resource "aws_sqs_queue" "events" {
  name                       = local.queue_names.events
  visibility_timeout_seconds = local.worker_timeout * 6
  message_retention_seconds  = 345600
  kms_master_key_id          = aws_kms_key.lab.arn
}

resource "aws_sqs_queue_redrive_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.processing_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "processing_dlq" {
  queue_url = aws_sqs_queue.processing_dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.events.arn]
  })
}

locals {
  queues = {
    events     = aws_sqs_queue.events
    delivery   = aws_sqs_queue.delivery_dlq
    processing = aws_sqs_queue.processing_dlq
  }
}

data "aws_iam_policy_document" "queues" {
  for_each = local.queues

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [each.value.arn]

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

  dynamic "statement" {
    for_each = each.key == "processing" ? [] : [1]
    content {
      sid       = "AllowOnlyLabRules"
      actions   = ["sqs:SendMessage"]
      resources = [each.value.arn]

      principals {
        type        = "Service"
        identifiers = ["events.amazonaws.com"]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = [for rule in values(local.event_rules) : rule.arn]
      }
    }
  }
}

resource "aws_sqs_queue_policy" "queues" {
  for_each  = local.queues
  queue_url = each.value.id
  policy    = data.aws_iam_policy_document.queues[each.key].json
}
