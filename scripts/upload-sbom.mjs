#!/usr/bin/env node
/**
 * upload-sbom.mjs
 *
 * Publishes a validated CycloneDX document to the ServiceNow SBOM Workspace and
 * waits for the ingestion queue to reach a terminal state, so that the build
 * reflects the true outcome rather than the mere acceptance of the request.
 *
 * Platform contract (see README section 7):
 *
 *   POST /api/core/upload                 body = BOM document, metadata = query parameters
 *   GET  /api/core/upload/status          ?bomRecordId=<sys_id>
 *
 * The upload API validates its own parameters: 'requestedBy=devops' conditionally
 * requires both 'buildId' and 'lifecycleStage', and 'lifecycleStage' admits only
 * 'production' or 'pre_production'. Business application and product model
 * identifiers are checked for existence against cmdb_ci_business_app and
 * cmdb_model respectively.
 *
 * Required environment:
 *   SN_INSTANCE           instance host, e.g. example.service-now.com
 *   SN_SBOM_USER          integration account holding sn_sbom_core.sbom_ingest
 *   SN_SBOM_PASSWORD      credential for that account
 *
 * Optional environment:
 *   SN_BUSINESS_APP_ID    sys_id on cmdb_ci_business_app
 *   SN_PRODUCT_MODEL_ID   sys_id on cmdb_model
 *   SN_BUILD_ID           build identifier (required when requestedBy=devops)
 *   SN_LIFECYCLE_STAGE    'production' | 'pre_production' (default pre_production)
 *   SN_SBOM_SOURCE        originating tool (default cyclonedx-npm)
 *   SN_REQUESTED_BY       default 'devops'
 *   SN_POLL_TIMEOUT_MS    default 600000
 *   SN_POLL_INTERVAL_MS   default 10000
 *
 * Usage:  node scripts/upload-sbom.mjs [sbom.json]
 * Exit:   0 processed, 1 rejected, failed or timed out
 */

import { readFile } from 'node:fs/promises';

const FILE = process.argv[2] ?? 'sbom.json';

const {
  SN_INSTANCE,
  SN_SBOM_USER,
  SN_SBOM_PASSWORD,
  SN_BUSINESS_APP_ID,
  SN_PRODUCT_MODEL_ID,
  SN_BUILD_ID,
  SN_LIFECYCLE_STAGE = 'pre_production',
  SN_SBOM_SOURCE = 'cyclonedx-npm',
  SN_REQUESTED_BY = 'devops',
  SN_POLL_TIMEOUT_MS = '600000',
  SN_POLL_INTERVAL_MS = '10000',
} = process.env;

const TERMINAL_SUCCESS = ['processed'];
const TERMINAL_FAILURE = ['error', 'timeout', 'skipped'];

function fail(message) {
  console.error(`FAIL  ${message}`);
  process.exit(1);
}

function assertEnvironment() {
  const missing = ['SN_INSTANCE', 'SN_SBOM_USER', 'SN_SBOM_PASSWORD'].filter((key) => !process.env[key]);
  if (missing.length > 0) {
    fail(`Missing required environment variable(s): ${missing.join(', ')}.`);
  }

  if (!['production', 'pre_production'].includes(SN_LIFECYCLE_STAGE)) {
    fail(`SN_LIFECYCLE_STAGE must be 'production' or 'pre_production', received '${SN_LIFECYCLE_STAGE}'.`);
  }

  // Mirrors the platform's conditional parameter rule, so the failure is local
  // and legible rather than a 400 from the instance.
  if (SN_REQUESTED_BY === 'devops' && !SN_BUILD_ID) {
    fail("SN_BUILD_ID is required when SN_REQUESTED_BY is 'devops'.");
  }

  if (!SN_BUSINESS_APP_ID && !SN_PRODUCT_MODEL_ID) {
    console.log(
      'WARN  Neither SN_BUSINESS_APP_ID nor SN_PRODUCT_MODEL_ID is set. The document will be ' +
        'ingested without being bound to a business application or product model, which limits ' +
        'its analytical value in the workspace.'
    );
  }
}

function authorisation() {
  return `Basic ${Buffer.from(`${SN_SBOM_USER}:${SN_SBOM_PASSWORD}`).toString('base64')}`;
}

function uploadUrl() {
  const url = new URL(`https://${SN_INSTANCE}/api/core/upload`);
  const params = {
    requestedBy: SN_REQUESTED_BY,
    buildId: SN_BUILD_ID,
    lifecycleStage: SN_LIFECYCLE_STAGE,
    businessApplicationId: SN_BUSINESS_APP_ID,
    productModelId: SN_PRODUCT_MODEL_ID,
    sbomSource: SN_SBOM_SOURCE,
    fetchVulnerabilityInfo: 'true',
    fetchPackageInfo: 'true',
    fetchLicenseInfo: 'true',
  };
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value);
  }
  return url;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function upload(document) {
  const url = uploadUrl();
  console.log(`Publishing ${FILE} to ${url.origin}${url.pathname}`);

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: authorisation(),
    },
    body: document,
  });

  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    fail(`Unparseable response (HTTP ${response.status}): ${text.slice(0, 500)}`);
  }

  if (!response.ok) {
    fail(`Upload rejected with HTTP ${response.status}: ${payload.message ?? text.slice(0, 500)}`);
  }

  const bomRecordId = payload.bomRecordId;
  if (!bomRecordId) {
    fail(`Upload returned no bomRecordId: ${JSON.stringify(payload)}`);
  }

  console.log(`Accepted. bomRecordId = ${bomRecordId}`);
  return bomRecordId;
}

async function pollUntilTerminal(bomRecordId) {
  const timeout = Number(SN_POLL_TIMEOUT_MS);
  const interval = Number(SN_POLL_INTERVAL_MS);
  const deadline = Date.now() + timeout;

  const url = new URL(`https://${SN_INSTANCE}/api/core/upload/status`);
  url.searchParams.set('bomRecordId', bomRecordId);

  let lastReported = null;

  while (Date.now() < deadline) {
    await sleep(interval);

    const response = await fetch(url, {
      headers: { Accept: 'application/json', Authorization: authorisation() },
    });
    const text = await response.text();

    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      console.log(`WARN  Unparseable status response (HTTP ${response.status}); retrying.`);
      continue;
    }

    // The status endpoint reports failure both through HTTP 500 and through a
    // status field; both are treated as terminal.
    const state = String(payload.status ?? '').toLowerCase();
    const detail = payload.detail ?? payload.message ?? '';

    if (state !== lastReported) {
      console.log(`Status: ${state || '(unreported)'}${detail ? ` — ${detail}` : ''}`);
      lastReported = state;
    }

    if (state === 'error' || TERMINAL_FAILURE.includes(state) || response.status >= 500) {
      fail(
        `Ingestion did not complete: ${detail || state || `HTTP ${response.status}`}. ` +
          `Inspect the record on sn_sbom_doc (status_reason, error_category) or the BOM Queue in the workspace.`
      );
    }

    if (TERMINAL_SUCCESS.includes(state) || state === 'success') {
      console.log(`\nIngestion complete. Document ${bomRecordId} processed.`);
      console.log(
        `Verify in the workspace: components with is_purl_valid = false must be absent, and ` +
          `dependency edges with is_direct_dep = false must be present.`
      );
      return;
    }
  }

  fail(
    `Timed out after ${timeout} ms awaiting a terminal state for ${bomRecordId}. ` +
      `The document may still be queued; inspect the BOM Queue before re-publishing.`
  );
}

async function main() {
  assertEnvironment();

  let document;
  try {
    document = await readFile(FILE, 'utf8');
  } catch (cause) {
    fail(`Cannot read ${FILE}: ${cause.message}`);
  }

  const bomRecordId = await upload(document);
  await pollUntilTerminal(bomRecordId);
}

await main();
