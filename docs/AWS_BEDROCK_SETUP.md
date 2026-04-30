# AWS Bedrock Setup for C

This project can run the C workflow without AWS through Static Playbook fallback. To use your own AWS account for real Claude analysis, configure Bedrock credentials locally.

## 1. Enable Bedrock Model Access

In the AWS console:

1. Open Amazon Bedrock.
2. Go to model access.
3. Enable access for the Anthropic Claude model configured in `.env`.

Current default:

```env
BEDROCK_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
```

If your account uses another region or model ID, change both values in `.env`.

## 2. IAM Permission

The user or role used by the backend needs at least:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel"
      ],
      "Resource": "*"
    }
  ]
}
```

For production, narrow `Resource` to the exact foundation model ARN.

## 3. Local `.env`

Do not commit `.env`.

For Docker Compose, the easiest setup is:

```env
LLM_PROVIDER=bedrock
BEDROCK_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_SESSION_TOKEN=
```

If you use temporary AWS credentials, fill `AWS_SESSION_TOKEN` too.

## 4. Start and Test

```powershell
docker compose up --build
```

Open the dashboard:

```text
http://localhost:3000
```

Login:

```text
admin@infrared.local
infrared123
```

Select an incident and click `Analyze`. If Bedrock succeeds, the saved LLM result uses the configured Bedrock model ID. If it fails, the backend logs `bedrock_analysis_failed` and falls back to `static-playbook`.

## 5. Important Notes

- Never paste AWS secrets into chat or commit them.
- `.env` is ignored by Git; `.env.example` is safe.
- Using an AWS CLI profile with Docker requires mounting `~/.aws` into the backend container. For this MVP, direct `.env` credentials are simpler.
- If the model is not enabled in your AWS region, Bedrock returns an access or validation error.
