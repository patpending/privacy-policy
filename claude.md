# Claude Context Guide

## Project Summary

Static website hosting for the **Dry Days** iPhone app privacy policy at **patpending.net**.

## Infrastructure

Infrastructure is managed in a separate repo: **patpending/patpending-infra**. This repo contains content only.

- **Domain**: patpending.net
- **S3 Bucket**: patpending-net-static-site
- **CloudFront ID**: E1CO8IABKIOQ2Q

## Deployment

Deployments happen automatically via GitHub Actions on push to main (when *.html files change).

### Manual cache invalidation
```bash
aws cloudfront create-invalidation --distribution-id E1CO8IABKIOQ2Q --paths "/*"
```

### Update privacy policy content
1. Edit `privacy-policy.html`
2. Push to main
3. GitHub Actions syncs to S3 and invalidates CloudFront automatically

## Key Files

| File | Purpose |
|------|---------|
| `privacy-policy.html` | The actual privacy policy content |
| `index.html` | Redirect to privacy-policy.html |
| `.github/workflows/deploy.yml` | CI/CD deploy workflow |
