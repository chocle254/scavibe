# Deployment Runbook

Scavibe supports two deployment layouts. The primary layout is one Vercel
Services project containing both applications. A Railway API plus Vercel
frontend remains the fallback if Vercel Services is unavailable.

| Service | Platform | Source root | Public responsibility |
| --- | --- | --- | --- |
| Frontend | Vercel Services | repository root | Next.js dashboard at `/` |
| API | Vercel Services | `backend` | FastAPI at `/api` |

## 1. Deploy the Vercel Services preview

1. Push this repository to a GitHub repository you control.
2. Import that repository in Vercel.
3. Keep the project root as the repository root.
4. In Vercel Project Settings → Build and Deployment, set the framework to
   **Services**. This is required because `vercel.json` defines `web` and `api`.
5. Deploy a Preview environment and record its exact `https://...vercel.app` URL.

The root `vercel.json` routes `/api/*` to FastAPI and all other paths to
Next.js. Do not expose `NVIDIA_API_KEY` to client-side Vercel variables.

## 2. Configure Vercel variables

Add these server-side variables to the Vercel project:

| Variable | Required value |
| --- | --- |
| `NVIDIA_API_KEY` | Server-side NVIDIA Build API key. |
| `SCAVIBE_NVIDIA_MODEL` | `nvidia/llama-3.3-nemotron-super-49b-v1`. |
| `SCAVIBE_ALLOWED_ORIGINS` | The exact Vercel preview origin, such as `https://scavibe-git-main-team.vercel.app`. |
| `GITHUB_TOKEN` | Not required for the current agent backbone. |
| `BLOB_READ_WRITE_TOKEN` | Not required for the current agent backbone. |

`SCAVIBE_ALLOWED_ORIGINS` accepts comma-separated exact origins and cannot be
`*`. Add the production Vercel origin before promoting to production.

## 3. Verify the deployed API before running an agent audit

```bash
curl -i https://YOUR-VERCEL-DOMAIN/api/health
```

Expected result: HTTP `200` and a JSON body containing `"status":"ok"`,
`"service":"scavibe-api"`, and `"version":"0.1.0"`.

Then create a read-only audit record:

```bash
curl -i -X POST https://YOUR-VERCEL-DOMAIN/api/audits \
  -H "Content-Type: application/json" \
  -d '{"repository_url":"https://github.com/acme/storefront","app_url":"https://storefront.example.com","live_target_confirmed":false}'
```

Expected result: HTTP `201`, `"status":"queued"`, and
`"target_mode":"sandbox-required"`. This request does not clone a repository,
send load traffic, call NVIDIA, or change GitHub.

## 4. Railway fallback

If Vercel Services is not enabled for the account, deploy `backend/` to Railway
with `backend/Dockerfile`. Use the Railway URL for
`NEXT_PUBLIC_BACKEND_URL`, and keep the exact Vercel origin in
`SCAVIBE_ALLOWED_ORIGINS`.

## 5. Connect the frontend when real audit submission is implemented

Set this Vercel Production and Preview variable, then redeploy:

```text
NEXT_PUBLIC_BACKEND_URL=/api
```

The `NEXT_PUBLIC_` prefix is required because this value is used in browser
code. It contains only a public route, never an API key.

## Current deployment boundary

The API validates supplied evidence bundles and calls specialist agents only
after `NVIDIA_API_KEY` is configured. GitHub cloning, sandbox creation, Locust/
k6 execution, report storage, SSE, and pull-request creation are not deployed.
