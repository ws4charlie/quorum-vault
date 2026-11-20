output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "log_file_validation" {
  value = aws_cloudtrail.this.enable_log_file_validation
}
