# AWS escalation from application code

Load when the code uses the AWS SDK. Apps expose AWS through code paths an
attacker can influence. Trace each SDK call for user input reaching it without an
allowlist.

- **DynamoDB** — user input in `TableName` (table pivot); `FilterExpression` by
  string concat (NoSQL-style injection); `Key` without an owner component (IDOR).
- **S3** — `Bucket` from body (bucket pivot); `Key` as `"uploads/"+params.path`
  (cross-tenant traversal); long-lived presigned URLs; public ACLs.
- **STS/IAM** — `RoleArn` from body (role pivot if the trust policy is loose).
- **Lambda** — `FunctionName` from body (arbitrary invocation).
- **SNS/SQS/EventBridge** — attacker-controlled `Topic`/`Message` (downstream
  deserialize).
- **Secrets Manager / SSM** — `SecretId`/`Name` from input (secret enumeration).
- **Cognito** — admin calls from a non-admin endpoint.
- **CloudWatch Logs** — `logGroupName` from query (read other services' logs).

Debug endpoints (`/health`, `/actuator/env`, `/api/admin/config`) often dump env
vars including `AWS_ACCESS_KEY_ID`, DB passwords, JWT secrets — hit unauth and
authed.

**Hard rules:** never run state-changing AWS calls against discovered
credentials; `aws sts get-caller-identity` only, then stop. Don't treat
local-checkout secrets as in scope unless a scanner confirmed them.
