output "website_url" {
  description = "The URL of the website"
  value       = "https://${local.domain_name}"
}

output "privacy_policy_url" {
  description = "Direct URL to the privacy policy"
  value       = "https://${local.domain_name}/privacy-policy.html"
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (for cache invalidation)"
  value       = aws_cloudfront_distribution.static_site.id
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.static_site.domain_name
}

output "s3_bucket_name" {
  description = "S3 bucket name for uploading content"
  value       = aws_s3_bucket.static_site.id
}
