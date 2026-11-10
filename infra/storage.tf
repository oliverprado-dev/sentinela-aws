resource "aws_s3_bucket" "lab" {
  bucket_prefix = "${local.name}-lab-"
  force_destroy = false
}

resource "aws_s3_bucket" "audit" {
  count         = var.create_cloudtrail ? 1 : 0
  bucket_prefix = "${local.name}-audit-"
  force_destroy = false
}

locals {
  buckets = merge(
    { lab = aws_s3_bucket.lab.id },
    var.create_cloudtrail ? { audit = aws_s3_bucket.audit[0].id } : {},
  )
}

resource "aws_s3_bucket_ownership_controls" "private" {
  for_each = local.buckets
  bucket   = each.value

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket = aws_s3_bucket.lab.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "audit" {
  count  = var.create_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.lab.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count  = var.create_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.lab.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "private" {
  for_each = local.buckets
  bucket   = each.value

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  count  = var.create_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  rule {
    id     = "lab-audit-retention"
    status = "Enabled"
    filter {}

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.private]
}

data "aws_iam_policy_document" "lab_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.lab.arn, "${aws_s3_bucket.lab.arn}/*"]

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
}

resource "aws_s3_bucket_policy" "lab" {
  bucket = aws_s3_bucket.lab.id
  policy = data.aws_iam_policy_document.lab_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.lab]
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${local.name}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled                 = true
    recovery_period_in_days = 7
  }

  server_side_encryption {
    enabled = true
  }
}
