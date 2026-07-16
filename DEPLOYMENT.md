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
| `GITHUB_TOKEN` | Required for private-repository intake and for user-approved draft PR creation. Public repository intake works without it, subject to GitHub's unauthenticated API limit. |
| `BLOB_READ_WRITE_TOKEN` | Not required for the current agent backbone. |

## 3. Enable Scavibe-owned disposable Vercel sandboxes

This is an optional, privileged capability. It is disabled until every variable
in this table is present on the **API service**. With Vercel Services, add them
to the same Vercel project as server-side variables. Do not prefix any of them
with `NEXT_PUBLIC_`.

| Variable | Exact rule |
| --- | --- |
| `VERCEL_SANDBOX_TOKEN` | A Vercel access token scoped to the Vercel account or team that owns disposable sandbox projects. The token must be able to create and delete projects and deployments. |
| `SCAVIBE_SANDBOX_ACCESS_KEY` | A random secret of at least 32 characters. Give it only to trusted Scavibe users. The browser supplies it as `X-Scavibe-Sandbox-Key`; it never reaches Vercel. |
| `SCAVIBE_SANDBOX_SIGNING_KEY` | A different random secret of at least 32 characters. Scavibe uses it only to sign short-lived sandbox tickets. Never expose it to a browser. |
| `VERCEL_SANDBOX_TEAM_ID` | Optional. Set this only when sandboxes belong to a Vercel team rather than the token owner's personal account. |
| `SCAVIBE_SANDBOX_TTL_SECONDS` | Optional integer from `300` through `1800`; default `900`. It sets the signed-ticket lifetime, not a Vercel auto-delete timer. |

Generate the two Scavibe secrets locally with separate commands:

```powershell
[Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

Before enabling the feature, connect the Vercel account's GitHub integration to
the repositories it is permitted to build. Vercel rejects imports that its Git
integration cannot read. For a private organization repository, Vercel also
applies its commit-author/team membership rules.

The sandbox project receives **zero user-supplied environment variables**. An
application that requires secrets to boot will fail its Vercel build or runtime;
Scavibe reports that failure and sends no load traffic. Never copy production
secrets into the disposable sandbox configuration.

`SCAVIBE_ALLOWED_ORIGINS` accepts comma-separated exact origins and cannot be
`*`. Add the production Vercel origin before promoting to production.

## 4. Verify the deployed API before running an agent audit

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

## 5. Railway fallback

If Vercel Services is not enabled for the account, deploy `backend/` to Railway
with `backend/Dockerfile`. Use the Railway URL for
`NEXT_PUBLIC_BACKEND_URL`, and keep the exact Vercel origin in
`SCAVIBE_ALLOWED_ORIGINS`.

## 6. Connect the frontend when real audit submission is implemented

Set this Vercel Production and Preview variable, then redeploy:

```text
NEXT_PUBLIC_BACKEND_URL=/api
```

The `NEXT_PUBLIC_` prefix is required because this value is used in browser
code. It contains only a public route, never an API key.

## Current deployment boundary

The API fetches public GitHub repositories at a pinned commit, runs bounded GET
load tests against user-authorized HTTPS sandbox URLs, and calls specialist
agents after `NVIDIA_API_KEY` is configured. When the sandbox variables are
configured, a trusted user can also create a no-secret Vercel project from the
pinned commit, test it only after Vercel reports `READY`, and trigger project
deletion after the test. The browser polls readiness for exactly 180 seconds.
If the browser is closed before the test begins, the signed ticket expires but
Vercel does not automatically delete the project; an operator must delete that
project in Vercel. Persistent report storage, authenticated end-user accounts,
scheduled orphan cleanup, route-aware browser journeys, SSE, and source-code
patch generation are not deployed. Draft PR creation is deployed for generated
audit artifacts and legal drafts only; it does not modify application source.
