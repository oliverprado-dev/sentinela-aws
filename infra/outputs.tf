output "account_id" {
  value = local.account_id
}

output "region" {
  value = local.region
}

output "response_mode" {
  value = var.response_mode
}

output "lab_bucket" {
  value = aws_s3_bucket.lab.id
}

output "audit_bucket" {
  value = try(aws_s3_bucket.audit[0].id, null)
}

output "cloudtrail_name" {
  value = try(aws_cloudtrail.lab[0].name, null)
}

output "guardduty_detector_id" {
  value = try(aws_guardduty_detector.lab[0].id, null)
}

output "incident_table" {
  value = aws_dynamodb_table.incidents.name
}

output "worker_log_group" {
  value = aws_cloudwatch_log_group.worker.name
}

output "queue_urls" {
  value = { for name, queue in local.queues : name => queue.id }
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
