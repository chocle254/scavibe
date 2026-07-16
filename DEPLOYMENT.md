# Deployment Runbook

Scavibe has two independently deployed services:

| Service | Platform | Source root | Public responsibility |
| --- | --- | --- | --- |
| Frontend | Vercel | repository root | Next.js dashboard |
| API | Railway | `backend` | Evidence validation and agent pipeline |

## 1. Deploy the Vercel preview

1. Push this repository to a GitHub repository you control.
2. Import that repository in Vercel.
3. Keep the project root as the repository root. Vercel detects Next.js.
4. Deploy a Preview environment. Record its exact `https://...vercel.app` URL.

The current frontend can deploy without an API URL because its audit interface
is still a visual pipeline preview. Do not enter an OpenAI API key in Vercel.

## 2. Deploy the Railway API

1. Create a Railway service from the same GitHub repository.
2. Set the Railway service **Root Directory** to `backend`.
3. Railway detects `backend/Dockerfile`; do not override its start command.
4. Create a public Railway domain and record the full `https://...` URL.
5. Add these Railway variables exactly:

| Variable | Required value |
| --- | --- |
| `NVIDIA_API_KEY` | Server-side NVIDIA Build API key. Never expose it to Vercel. |
| `SCAVIBE_NVIDIA_MODEL` | `nvidia/llama-3.3-nemotron-super-49b-v1` for the selected NVIDIA free trial endpoint. |
| `SCAVIBE_ALLOWED_ORIGINS` | The exact Vercel preview origin, for example `https://scavibe-git-main-team.vercel.app`. |
| `GITHUB_TOKEN` | Not required for the current agent backbone; required only when repository integration is built. |
| `BLOB_READ_WRITE_TOKEN` | Not required for the current agent backbone; required only when report storage is built. |

`SCAVIBE_ALLOWED_ORIGINS` accepts a comma-separated list. Add the production
Vercel origin before promoting the frontend to production. The value cannot be
`*`.

## 3. Verify the deployed API before supplying an OpenAI key

Run this exact request after Railway reports a successful deployment:

```bash
curl -i https://YOUR-RAILWAY-DOMAIN/health
```

Expected result: HTTP `200` and a JSON body containing `"status":"ok"`,
`"service":"scavibe-api"`, and `"version":"0.1.0"`.

Then create a read-only audit record:

```bash
curl -i -X POST https://YOUR-RAILWAY-DOMAIN/audits \
  -H "Content-Type: application/json" \
  -d '{"repository_url":"https://github.com/acme/storefront","app_url":"https://storefront.example.com","live_target_confirmed":false}'
```

Expected result: HTTP `201`, `"status":"queued"`, and
`"target_mode":"sandbox-required"`. This request does not clone a repository,
send load traffic, call OpenAI, or change GitHub.

## 4. Connect the frontend when real audit submission is implemented

Set this Vercel Production and Preview variable, then redeploy the frontend:

```text
NEXT_PUBLIC_BACKEND_URL=https://YOUR-RAILWAY-DOMAIN
```

The `NEXT_PUBLIC_` prefix is required because this value is used in browser
code. It contains only the public API URL, never an API key.

## Current deployment boundary

The deployed API validates supplied evidence bundles and calls specialist
agents only after `NVIDIA_API_KEY` is configured. It uses NVIDIA's selected
free trial endpoint, which does not provide a production uptime guarantee.
GitHub cloning, sandbox creation, Locust/k6 execution, report storage, SSE, and
pull-request creation are not deployed yet. The service does not claim to run
those integrations.
