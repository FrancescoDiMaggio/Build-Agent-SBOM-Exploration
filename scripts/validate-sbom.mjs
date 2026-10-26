#!/usr/bin/env node
/**
 * validate-sbom.mjs
 *
 * Conformance gate executed before a derived SBOM is offered to the ServiceNow
 * SBOM Workspace. It reproduces, locally and offline, the admission criteria
 * that the platform applies server-side, so that a defective document fails the
 * build rather than being accepted into an inventory where it contributes
 * nothing.
 *
 * The criteria mirror three observed platform artefacts (see README section 4):
 *
 *   sn_sbom_core.BOMValidationApi        format identification, minimum fields
 *   sn_sbom_core.BOMParserApiDelegator   supported specification versions
 *   sn_sbom_core.PurlUtils.isValid()     Package URL admissibility
 *
 * Usage:  node scripts/validate-sbom.mjs [sbom.json]
 * Exit:   0 conformant, 1 non-conformant or unreadable
 */

import { readFile } from 'node:fs/promises';

const FILE = process.argv[2] ?? 'sbom.json';

/** Specification versions for which the platform dispatches a parser. */
const SUPPORTED_SPEC_VERSIONS = ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6'];

/** Ecosystems covered by the deps.dev integration, by PURL type. */
const ENRICHED_ECOSYSTEMS = ['golang', 'go', 'npm', 'cargo', 'maven', 'pypi', 'nuget'];

const errors = [];
const warnings = [];

/**
 * Faithful reproduction of sn_sbom_core.PurlUtils.isValid().
 *
 * The decisive clause is the version check: the platform requires the version
 * segment to be percent-encoded, which rejects unresolved semantic-version
 * ranges such as '^4.17.21'. Components failing this check are persisted with
 * is_purl_valid = false and are excluded from every vulnerability enrichment
 * query, without any error being raised.
 */
function isValidPurl(purl) {
  if (!purl || typeof purl !== 'string' || !purl.trim()) return false;

  const colon = purl.indexOf(':');
  if (colon < 0) return false;
  if (purl.slice(0, colon) !== 'pkg') return false;

  let remainder = purl.slice(colon + 1).trim().replace(/^\/+/g, '');

  // A type component must be present and followed by something.
  const head = remainder.split('/', 2);
  if (!head[0] || !head[1]) return false;
  remainder = remainder.slice(remainder.indexOf('/') + 1);

  // Qualifiers and subpath are optional and not subject to validation.
  const qualifierIdx = remainder.indexOf('?');
  if (qualifierIdx > -1) remainder = remainder.substring(0, qualifierIdx);
  const subpathIdx = remainder.indexOf('#');
  if (subpathIdx > -1) remainder = remainder.substring(0, subpathIdx);

  if (remainder.includes('@')) {
    const at = remainder.indexOf('@');
    const rawVersion = remainder.substring(at + 1);
    let decoded;
    try {
      decoded = decodeURIComponent(rawVersion);
    } catch {
      return false;
    }
    const reEncoded = encodeURIComponent(decoded).replace(/%3A/g, ':').replace(/%2B/g, '+');
    if (rawVersion !== reEncoded) return false;
    remainder = remainder.substring(0, at);
  }

  const segments = remainder.split('/');
  let name = null;
  let namespace = null;
  if (segments.length > 1) {
    name = segments[segments.length - 1];
    namespace = segments.slice(0, -1).join('/');
  } else {
    name = segments[0];
  }

  if (!name) return false;
  if (!namespace && name.includes(':')) return false;

  return true;
}

function purlType(purl) {
  const match = /^pkg:([^/]+)\//.exec(purl ?? '');
  return match ? match[1].toLowerCase() : null;
}

/**
 * Decoded version segment of a Package URL, or null when none is declared.
 */
function purlVersion(purl) {
  if (typeof purl !== 'string') return null;
  let remainder = purl.split('?')[0].split('#')[0];
  const at = remainder.lastIndexOf('@');
  // A leading '@' belongs to an npm scope, not to a version.
  if (at <= 0 || remainder.lastIndexOf('/') > at) return null;
  const raw = remainder.substring(at + 1);
  if (!raw) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/**
 * Semantic-version range operators. These must not survive into an SBOM:
 * a range identifies a set of releases, not the artefact that was built.
 *
 * Note that the platform's own isValid() does not catch all of them. It rejects
 * '^4.17.21', because '^' is percent-encoded by encodeURIComponent, but accepts
 * '~4.17.0' and a version-less PURL, because '~' is an unreserved character and
 * the version segment is optional. Verified against the instance. The platform
 * flag is therefore a necessary but insufficient condition for correlation, and
 * this gate is deliberately stricter than the platform.
 */
const RANGE_PATTERN = /[\^~><=*|\s]|^v?\d+\.x|\.x$/;

function validateCycloneDx(bom) {
  const spec = bom.specVersion;

  if (!spec) {
    errors.push('Missing required field: specVersion.');
  } else if (!SUPPORTED_SPEC_VERSIONS.includes(spec)) {
    errors.push(
      `Specification version ${spec} is not dispatchable by the platform. ` +
        `BOMParserApiDelegator resolves no parser beyond 1.6; regenerate with --spec-version 1.6.`
    );
  }

  // The platform exempts spec 1.5 from the document version requirement.
  if (spec !== '1.5' && (bom.version === undefined || bom.version === null || bom.version === '')) {
    errors.push('Missing required field: version.');
  }

  const main = bom.metadata?.component;
  if (!main?.name) errors.push('Missing required field: metadata.component.name.');
  if (!main?.type) {
    errors.push('Missing required field: metadata.component.type. Generate with --mc-type application.');
  }

  const components = Array.isArray(bom.components) ? bom.components : [];
  if (components.length === 0) {
    errors.push(
      'The document declares no components. For a ServiceNow Fluent project this is the ' +
        'expected outcome of generating with --omit dev, since the whole dependency set is ' +
        'declared under devDependencies.'
    );
  }

  const invalidPurls = [];
  const missingPurls = [];
  const inexactPurls = [];
  const missingVersions = [];
  const missingLicences = [];
  const unenrichable = new Set();

  for (const component of components) {
    const label = component.purl || `${component.group ?? ''}${component.name ?? '(unnamed)'}`;

    if (!component.purl) {
      missingPurls.push(label);
    } else if (!isValidPurl(component.purl)) {
      invalidPurls.push(component.purl);
    } else {
      const type = purlType(component.purl);
      if (type && !ENRICHED_ECOSYSTEMS.includes(type)) unenrichable.add(type);

      // Admissible to the platform, yet still uncorrelatable: a range or an
      // absent version identifies no single release.
      const version = purlVersion(component.purl);
      if (version === null || RANGE_PATTERN.test(version)) {
        inexactPurls.push(component.purl);
      }
    }

    if (!component.version) missingVersions.push(label);

    const licences = component.licenses;
    if (!Array.isArray(licences) || licences.length === 0) missingLicences.push(label);
  }

  if (invalidPurls.length > 0) {
    errors.push(
      `${invalidPurls.length} component(s) carry a Package URL the platform will reject, ` +
        `yielding is_purl_valid = false and silent exclusion from all vulnerability enrichment. ` +
        `This is the signature of generation against an unresolved dependency tree: run 'npm ci' ` +
        `against a committed lock file before generating.\n         ` +
        invalidPurls.slice(0, 10).join('\n         ') +
        (invalidPurls.length > 10 ? `\n         ... and ${invalidPurls.length - 10} more` : '')
    );
  }

  if (missingPurls.length > 0) {
    errors.push(
      `${missingPurls.length} component(s) carry no Package URL and cannot be correlated ` +
        `against vulnerability intelligence: ${missingPurls.slice(0, 5).join(', ')}` +
        (missingPurls.length > 5 ? ', ...' : '')
    );
  }

  if (inexactPurls.length > 0) {
    errors.push(
      `${inexactPurls.length} component(s) carry a Package URL that the platform will accept ` +
        `as valid but that identifies no single release, because the version is a range or is ` +
        `absent. Such components are enriched against an indeterminate target. Note that the ` +
        `platform's own check does not catch this class of defect.\n         ` +
        inexactPurls.slice(0, 10).join('\n         ') +
        (inexactPurls.length > 10 ? `\n         ... and ${inexactPurls.length - 10} more` : '')
    );
  }

  if (missingVersions.length > 0) {
    warnings.push(
      `${missingVersions.length} component(s) declare no version: ` +
        `${missingVersions.slice(0, 5).join(', ')}${missingVersions.length > 5 ? ', ...' : ''}`
    );
  }

  if (missingLicences.length > 0) {
    warnings.push(
      `${missingLicences.length} component(s) declare no licence; these will surface in the ` +
        `platform with has_missing_licenses set and require manual resolution.`
    );
  }

  if (unenrichable.size > 0) {
    warnings.push(
      `PURL type(s) outside the enriched ecosystems (${[...unenrichable].join(', ')}): ` +
        `deps.dev will not return package intelligence for these components.`
    );
  }

  const dependencies = Array.isArray(bom.dependencies) ? bom.dependencies : [];
  const edges = dependencies.reduce((n, d) => n + (Array.isArray(d.dependsOn) ? d.dependsOn.length : 0), 0);
  if (edges === 0) {
    warnings.push(
      'The document declares no dependency edges. No transitive relationships will be ' +
        'reconstructed on sn_sbom_comp_relationship, which is the coverage expectation of the ' +
        'current minimum elements.'
    );
  }

  return { components: components.length, edges, spec };
}

async function main() {
  let raw;
  try {
    raw = await readFile(FILE, 'utf8');
  } catch (cause) {
    console.error(`FAIL  Cannot read ${FILE}: ${cause.message}`);
    process.exit(1);
  }

  let bom;
  try {
    bom = JSON.parse(raw);
  } catch (cause) {
    console.error(`FAIL  ${FILE} is not valid JSON: ${cause.message}`);
    process.exit(1);
  }

  // Format identification, as performed by BOMValidationApi.validateJSON().
  if (!bom.bomFormat && !bom.spdxVersion) {
    console.error(
      `FAIL  Unable to identify the format of ${FILE}. The platform requires either a ` +
        `'bomFormat' key (CycloneDX) or an 'spdxVersion' key (SPDX). A package.json, or a ` +
        `generator's native output format, is rejected with error_category = unsupported.`
    );
    process.exit(1);
  }

  let summary = {};

  if (bom.bomFormat === 'CycloneDX') {
    summary = validateCycloneDx(bom);
  } else if (bom.spdxVersion) {
    // SPDX JSON is admissible; its minimum fields are enforced separately.
    for (const field of ['SPDXID', 'spdxVersion', 'dataLicense', 'documentNamespace']) {
      if (!bom[field]) errors.push(`Missing required SPDX field: ${field}.`);
    }
    if (!bom.creationInfo?.created) errors.push('Missing required SPDX field: creationInfo.created.');
    if (!bom.creationInfo?.creators?.length) errors.push('Missing required SPDX field: creationInfo.creators.');
  } else {
    errors.push(`Unsupported bomFormat '${bom.bomFormat}'. The platform accepts CycloneDX and SPDX only.`);
  }

  console.log(`Document     ${FILE}`);
  console.log(`Format       ${bom.bomFormat ?? 'SPDX'} ${summary.spec ?? bom.spdxVersion ?? ''}`);
  if (summary.components !== undefined) {
    console.log(`Components   ${summary.components}`);
    console.log(`Dependencies ${summary.edges} edge(s)`);
  }
  console.log('');

  for (const warning of warnings) console.log(`WARN  ${warning}`);
  for (const error of errors) console.error(`FAIL  ${error}`);

  if (errors.length > 0) {
    console.error(`\n${errors.length} blocking issue(s). The document was not offered to the instance.`);
    process.exit(1);
  }

  console.log(
    `\nConformant with the ServiceNow ingestion contract` +
      (warnings.length > 0 ? ` (${warnings.length} advisory warning(s)).` : '.')
  );
}

await main();
