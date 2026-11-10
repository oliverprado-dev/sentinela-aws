data "aws_iam_policy_document" "assume_worker" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "worker" {
  name               = "${local.name}-worker"
  assume_role_policy = data.aws_iam_policy_document.assume_worker.json
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/aws/lambda/${local.name}-worker"
  retention_in_days = 30
}

locals {
  worker_statements = concat(
    [
      {
        Sid      = "PollIncidentQueue"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.events.arn
      },
      {
        Sid      = "DecryptIncidentQueue"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.lab.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                    = "sqs.${local.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sqs:arn" = local.queue_arns.events
          }
        }
      },
      {
        Sid      = "WriteFunctionLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.worker.arn}:*"
      },
      {
        Sid      = "JournalIncidents"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.incidents.arn
      },
      {
        Sid      = "ReadLabBucketBaseline"
        Effect   = "Allow"
        Action   = ["s3:GetBucketPublicAccessBlock"]
        Resource = aws_s3_bucket.lab.arn
      },
      {
        Sid      = "PublishIncidentAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid      = "UseAlertKeyViaSNS"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = aws_kms_key.lab.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                         = "sns.${local.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sns:topicArn" = local.topic_arn
          }
        }
      },
    ],
    var.response_mode == "enforce" ? [
      {
        Sid      = "RestoreLabBucketBaseline"
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock"]
        Resource = aws_s3_bucket.lab.arn
      },
    ] : [],
  )
}

resource "aws_iam_role_policy" "worker" {
  name = "${local.name}-scope"
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.worker_statements
  })
}

data "archive_file" "worker" {
  type             = "zip"
  output_path      = "${path.module}/sentinela.zip"
  output_file_mode = "0644"

  dynamic "source" {
    for_each = fileset("${path.module}/../src", "sentinela/*")
    content {
      filename = source.value
      content  = file("${path.module}/../src/${source.value}")
    }
  }
}

resource "aws_lambda_function" "worker" {
  function_name    = "${local.name}-worker"
  filename         = data.archive_file.worker.output_path
  source_code_hash = data.archive_file.worker.output_base64sha256
  role             = aws_iam_role.worker.arn
  handler          = "sentinela.entrypoint.handler"
  runtime          = "python3.12"
  timeout          = local.worker_timeout
  memory_size      = 128

  environment {
    variables = {
      TARGET_ACCOUNT          = local.account_id
      LAB_BUCKET              = aws_s3_bucket.lab.id
      WORKER_ROLE_ARN         = aws_iam_role.worker.arn
      RECONCILIATION_RULE_ARN = aws_cloudwatch_event_rule.reconciliation.arn
      RESPONSE_MODE           = var.response_mode
      RETENTION_DAYS          = tostring(var.incident_retention_days)
      INCIDENT_TABLE          = aws_dynamodb_table.incidents.name
      ALERTS_TOPIC_ARN        = aws_sns_topic.alerts.arn
    }
  }

  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
    log_group             = aws_cloudwatch_log_group.worker.name
  }

  depends_on = [aws_iam_role_policy.worker, aws_s3_bucket_public_access_block.lab]
}

resource "aws_lambda_event_source_mapping" "queue" {
  event_source_arn        = aws_sqs_queue.events.arn
  function_name           = aws_lambda_function.worker.arn
  batch_size              = 1
  function_response_types = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = 2
  }

  depends_on = [aws_iam_role_policy.worker, aws_sqs_queue_redrive_policy.events]
}
