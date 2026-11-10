mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = <<-JSON
        {"Version":"2012-10-17","Statement":[]}
      JSON
    }
  }
}

override_resource {
  target          = aws_s3_bucket.lab
  override_during = plan
  values = {
    id  = "sentinela-aws-lab-exemplo"
    arn = "arn:aws:s3:::sentinela-aws-lab-exemplo"
  }
}

run "observe_denies_s3_mutation_by_omission" {
  command = plan

  assert {
    condition = (
      toset(flatten([
        for stmt in jsondecode(aws_iam_role_policy.worker.policy).Statement : stmt.Action
        if anytrue([for action in stmt.Action : startswith(action, "s3:")])
      ])) == toset(["s3:GetBucketPublicAccessBlock"])
    )
    error_message = "O modo observe deve ter somente leitura de BPA no S3."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.lab.block_public_acls,
      aws_s3_bucket_public_access_block.lab.ignore_public_acls,
      aws_s3_bucket_public_access_block.lab.block_public_policy,
      aws_s3_bucket_public_access_block.lab.restrict_public_buckets,
    ])
    error_message = "As quatro proteções do bucket devem iniciar ativas."
  }

  assert {
    condition = (
      aws_lambda_function.worker.environment[0].variables["RESPONSE_MODE"] == "observe" &&
      aws_sqs_queue.events.visibility_timeout_seconds >= 6 * aws_lambda_function.worker.timeout &&
      aws_sqs_queue.events.kms_master_key_id == aws_kms_key.lab.arn &&
      aws_sqs_queue.delivery_dlq.kms_master_key_id == aws_kms_key.lab.arn &&
      aws_sqs_queue.processing_dlq.kms_master_key_id == aws_kms_key.lab.arn &&
      contains(aws_lambda_event_source_mapping.queue.function_response_types, "ReportBatchItemFailures") &&
      jsondecode(aws_sqs_queue_redrive_policy.events.redrive_policy).maxReceiveCount == 5 &&
      length(aws_cloudwatch_event_target.queue) == 3 &&
      length(aws_cloudwatch_metric_alarm.queues) == 3
    )
    error_message = "Modo seguro, visibilidade, retry, destinos e alarmes devem permanecer conectados."
  }

  assert {
    condition = (
      aws_cloudtrail.lab[0].enable_logging &&
      aws_cloudtrail.lab[0].enable_log_file_validation &&
      one(aws_cloudtrail.lab[0].event_selector).read_write_type == "WriteOnly" &&
      one(aws_cloudtrail.lab[0].event_selector).include_management_events &&
      one(aws_dynamodb_table.incidents.ttl).enabled
    )
    error_message = "A trilha e o diário devem preservar o desenho de auditoria."
  }
}

run "enforce_is_scoped_to_the_lab_bucket" {
  command = plan

  variables {
    response_mode = "enforce"
  }

  assert {
    condition = (
      tolist([
        for stmt in jsondecode(aws_iam_role_policy.worker.policy).Statement : stmt.Resource
        if contains(stmt.Action, "s3:PutBucketPublicAccessBlock")
      ]) == tolist(["arn:aws:s3:::sentinela-aws-lab-exemplo"]) &&
      alltrue([
        for stmt in jsondecode(aws_iam_role_policy.worker.policy).Statement : stmt.Resource != "*"
      ])
    )
    error_message = "A função deve poder corrigir exclusivamente o bucket de laboratório."
  }

  assert {
    condition = (
      aws_lambda_function.worker.environment[0].variables["RESPONSE_MODE"] == "enforce" &&
      aws_lambda_function.worker.environment[0].variables["LAB_BUCKET"] == "sentinela-aws-lab-exemplo" &&
      jsondecode(aws_cloudwatch_event_rule.cloudtrail.event_pattern).detail.requestParameters.bucketName[0] == "sentinela-aws-lab-exemplo" &&
      contains(jsondecode(aws_cloudwatch_event_rule.cloudtrail.event_pattern).detail.eventName, "DeleteBucketPublicAccessBlock") &&
      contains(jsondecode(aws_cloudwatch_event_rule.guardduty.event_pattern).detail.type, "Exfiltration:S3/AnomalousBehavior")
    )
    error_message = "O escopo do worker e os filtros dos dois detectores devem coincidir com o projeto."
  }
}

run "reuses_existing_detection_services" {
  command = plan

  variables {
    create_cloudtrail         = false
    create_guardduty_detector = false
  }

  assert {
    condition = (
      length(aws_cloudtrail.lab) == 0 &&
      length(aws_s3_bucket.audit) == 0 &&
      length(aws_guardduty_detector.lab) == 0 &&
      length(aws_cloudwatch_event_target.queue) == 3
    )
    error_message = "O reuso não deve assumir a propriedade de serviços existentes."
  }
}

run "enables_s3_protection_when_detector_is_created" {
  command = plan

  variables {
    create_guardduty_detector = true
  }

  assert {
    condition = (
      aws_guardduty_detector.lab[0].enable &&
      aws_guardduty_detector_feature.s3[0].name == "S3_DATA_EVENTS" &&
      aws_guardduty_detector_feature.s3[0].status == "ENABLED"
    )
    error_message = "O detector novo deve habilitar o plano S3 Protection."
  }
}

run "rejects_unknown_response_mode" {
  command = plan

  variables {
    response_mode = "unsafe"
  }

  expect_failures = [var.response_mode]
}
