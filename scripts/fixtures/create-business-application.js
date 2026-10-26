/* =====================================================================
 * create-business-application.js
 *
 * CMDB fixture for the Build Agent SBOM Exploration research repository.
 *
 * Creates the Business Application "Marketing Tender Portal" on
 * cmdb_ci_business_app and binds it to the BOM entity produced by ingesting
 * sbom_example.json, so that the SBOM Workspace can be captured with coherent,
 * populated data.
 *
 * Execution context
 *   Scope        global
 *   Mechanism    background script (System Definition > Scripts - Background)
 *   Side effects one cmdb_ci_business_app record, one field update on
 *                sn_sbom_component. Nothing else is written.
 *
 * Idempotent: re-running updates the existing record rather than cloning it.
 *
 * Reference resolution is defensive. Users, groups, departments and business
 * units are resolved by name with fallbacks, because demo data differs between
 * instances. Fields that cannot be resolved coherently are LEFT EMPTY rather
 * than filled with an approximation: a blank field is honest, whereas a wrong
 * one becomes a false datum visible in a screenshot. This is why Company and
 * Publisher are only set when the instance declares a primary company, and why
 * Vendor is never set at all on an application classified as homegrown.
 * ===================================================================== */

var APP_NAME = 'Marketing Tender Portal';

/* BOM entity created by ingesting sbom_example.json (marketing-tender-portal
 * 1.0.0). Re-point this constant if the document is re-ingested, since a new
 * entity record is created each time. */
var BOM_ENTITY = '03b2b62b0fc81b10083782d300d1b2b3';
var PURL = 'pkg:npm/marketing-tender-portal@1.0.0';

var report = [];
function log(line) { report.push(line); }

/* ------------------------------------------------------------------ *
 * Reference resolution
 * ------------------------------------------------------------------ */

function pickUser(userNames) {
  var i, gr;
  for (i = 0; i < userNames.length; i++) {
    gr = new GlideRecord('sys_user');
    gr.addQuery('user_name', userNames[i]);
    gr.addQuery('active', true);
    gr.setLimit(1);
    gr.query();
    if (gr.next()) return { id: gr.getUniqueValue(), label: gr.getValue('name') };
  }
  gr = new GlideRecord('sys_user');
  gr.addQuery('active', true);
  gr.addNotNullQuery('first_name');
  gr.orderBy('user_name');
  gr.setLimit(1);
  gr.query();
  return gr.next() ? { id: gr.getUniqueValue(), label: gr.getValue('name') } : { id: null, label: '(none)' };
}

function pickByName(table, names) {
  var i, gr;
  for (i = 0; i < names.length; i++) {
    gr = new GlideRecord(table);
    gr.addQuery('name', 'CONTAINS', names[i]);
    gr.setLimit(1);
    gr.query();
    if (gr.next()) return { id: gr.getUniqueValue(), label: gr.getValue('name') };
  }
  gr = new GlideRecord(table);
  gr.orderBy('name');
  gr.setLimit(1);
  gr.query();
  return gr.next() ? { id: gr.getUniqueValue(), label: gr.getValue('name') } : { id: null, label: '(none)' };
}

/* Only a company the instance itself declares as primary is admissible as the
 * owner of a homegrown application. Arbitrary vendor records are not. */
function primaryCompany() {
  var gr = new GlideRecord('core_company');
  gr.addQuery('primary', true);
  gr.setLimit(1);
  gr.query();
  if (gr.next()) return { id: gr.getUniqueValue(), label: gr.getValue('name') };
  return { id: null, label: '(none declared)' };
}

var owner = pickUser(['abel.tuter', 'beth.anglin', 'fred.luddy', 'admin']);
var manager = pickUser(['beth.anglin', 'david.loo', 'fred.luddy', 'admin']);
var support = pickUser(['david.loo', 'abel.tuter', 'admin']);
var portfolio = pickUser(['fred.luddy', 'beth.anglin', 'admin']);

var supportGroup = pickByName('sys_user_group', ['Application Development', 'Software', 'Service Desk']);
var changeGroup = pickByName('sys_user_group', ['Change Management', 'Application Development', 'Service Desk']);
var department = pickByName('cmn_department', ['Marketing', 'Sales', 'IT']);
var businessUnit = pickByName('business_unit', ['Marketing', 'Sales', 'Technology']);
var location = pickByName('cmn_location', ['Milan', 'Rome', 'Italy', 'London']);
var company = primaryCompany();

/* cmn_cost_center is empty on many developer instances; absence is tolerated. */
var costCentre = { id: null, label: '(none)' };
var ccProbe = new GlideRecord('cmn_cost_center');
ccProbe.setLimit(1);
ccProbe.query();
if (ccProbe.hasNext()) costCentre = pickByName('cmn_cost_center', ['Marketing', 'Sales', 'IT']);

/* ------------------------------------------------------------------ *
 * Dates, expressed relative to execution so the record never looks stale
 * ------------------------------------------------------------------ */

var now = new GlideDateTime();
var installed = new GlideDateTime(); installed.addDaysUTC(-418);
var started = new GlideDateTime(); started.addDaysUTC(-455);
var discovered = new GlideDateTime(); discovered.addDaysUTC(-410);
var nextAssess = new GlideDateTime(); nextAssess.addDaysUTC(118);
var contractEnd = new GlideDateTime(); contractEnd.addDaysUTC(287);

/* ------------------------------------------------------------------ *
 * Upsert
 * ------------------------------------------------------------------ */

var ba = new GlideRecord('cmdb_ci_business_app');
ba.addQuery('name', APP_NAME);
ba.setLimit(1);
ba.query();

var existed = ba.next();
if (!existed) {
  ba = new GlideRecord('cmdb_ci_business_app');
  ba.initialize();
}

ba.setValue('name', APP_NAME);
ba.setValue('short_description',
  'Public-facing portal through which marketing agencies register, receive tender invitations ' +
  'and submit competitive bids. Node.js single-page application with a REST API, deployed on ' +
  'managed cloud infrastructure and released through a CI/CD pipeline that publishes a ' +
  'CycloneDX SBOM on every build.');
ba.setValue('comments',
  'Subject application of the Build Agent SBOM Exploration research repository. Its dependency ' +
  'manifest is the source artefact for the package.json -> CycloneDX transformation documented ' +
  'there. The correlation ID carries the Package URL of the corresponding BOM entity.');

/* Classification */
ba.setValue('application_type', 'homegrown');
ba.setValue('architecture_type', 'web');
ba.setValue('technology_stack', 'mern');
ba.setValue('platform', 'aws');
ba.setValue('install_type', 'cloud');
ba.setValue('environment', 'Production');
ba.setValue('category', 'Software');
ba.setValue('subcategory', 'Business Application');

/* Lifecycle and risk posture.
 * install_status on this table is APM-specific: 0 Implementing, 1 In Production,
 * 2 Pilot, 3 Retired, 4 Under Evaluation. operational_status 1 is Operational. */
ba.setValue('install_status', 1);
ba.setValue('operational_status', 1);
ba.setValue('business_criticality', 'high');
ba.setValue('data_classification', 'confidential');
ba.setValue('emergency_tier', 'business_critical');
ba.setValue('audience_type', 'b2b');
ba.setValue('currency', 'current');
ba.setValue('active', true);
ba.setValue('monitor', true);
ba.setValue('certified', true);

/* Attestation */
ba.setValue('attested', true);
ba.setValue('attestation_status', 'Attested');
ba.setValue('attestation_score', 92);
ba.setValue('attested_date', now.getDisplayValueInternal());
if (owner.id) ba.setValue('attested_by', owner.id);

/* Scale and cost */
ba.setValue('user_base', '999');
ba.setValue('active_user_count', 742);
ba.setValue('cost', 185000);
ba.setValue('cost_cc', 'EUR');

/* Addressing. The correlation ID deliberately carries the PURL, which ties the
 * configuration item to the BOM entity by the same key the SBOM uses. */
ba.setValue('url', 'https://tenders.marketing.example.com');
ba.setValue('dns_domain', 'marketing.example.com');
ba.setValue('fqdn', 'tenders.marketing.example.com');
ba.setValue('model_number', 'MTP-1.0.0');
ba.setValue('correlation_id', PURL);
ba.setValue('discovery_source', 'Manual Entry');

/* People and organisation */
if (owner.id) { ba.setValue('it_application_owner', owner.id); ba.setValue('owned_by', owner.id); }
if (manager.id) { ba.setValue('managed_by', manager.id); ba.setValue('assigned_to', manager.id); }
if (support.id) ba.setValue('supported_by', support.id);
if (portfolio.id) ba.setValue('application_manager', portfolio.id);
if (supportGroup.id) ba.setValue('support_group', supportGroup.id);
if (changeGroup.id) { ba.setValue('assignment_group', changeGroup.id); ba.setValue('change_control', changeGroup.id); }
if (department.id) ba.setValue('department', department.id);
if (businessUnit.id) ba.setValue('business_unit', businessUnit.id);
if (location.id) ba.setValue('location', location.id);
if (costCentre.id) ba.setValue('cost_center', costCentre.id);

/* Only when the instance declares one. Never a vendor: the application is
 * homegrown, so an external vendor would contradict its classification. */
if (company.id) {
  ba.setValue('company', company.id);
  ba.setValue('manufacturer', company.id);
}
ba.setValue('vendor', '');
ba.setValue('support_vendor', '');

/* Dates */
ba.setValue('install_date', installed.getDisplayValueInternal());
ba.setValue('start_date', started.getDisplayValueInternal());
ba.setValue('first_discovered', discovered.getDisplayValueInternal());
ba.setValue('last_discovered', now.getDisplayValueInternal());
ba.setValue('next_assessment_date', nextAssess.getDate().getValue());
ba.setValue('contract_end_date', contractEnd.getDate().getValue());

var appId;
if (existed) {
  ba.update();
  appId = ba.getUniqueValue();
  log('Business Application UPDATED: ' + appId);
} else {
  appId = ba.insert();
  log('Business Application CREATED: ' + appId);
}

/* ------------------------------------------------------------------ *
 * Bind the SBOM to the application
 * ------------------------------------------------------------------ */

var ent = new GlideRecord('sn_sbom_component');
if (ent.get(BOM_ENTITY)) {
  var previous = ent.getValue('business_app');
  ent.setValue('business_app', appId);
  ent.update();

  var after = new GlideRecord('sn_sbom_component');
  after.get(BOM_ENTITY);
  log('BOM entity bound: ' + after.getValue('display_name') +
      ' (was ' + (previous || 'empty') + ')');
  log('Binding effective: ' + (after.getValue('business_app') === appId ? 'yes' : 'NO'));
} else {
  log('BOM entity ' + BOM_ENTITY + ' not found. Re-ingest sbom_example.json and update the constant.');
}

/* ------------------------------------------------------------------ *
 * Verification
 * ------------------------------------------------------------------ */

var v = new GlideRecord('cmdb_ci_business_app');
if (v.get(appId)) {
  var fields = [
    'number', 'install_status', 'operational_status', 'business_criticality',
    'data_classification', 'application_type', 'technology_stack', 'environment',
    'it_application_owner', 'support_group', 'department', 'business_unit',
    'location', 'company', 'cost_center', 'correlation_id'
  ];
  log('');
  for (var k = 0; k < fields.length; k++) {
    var dv = v.getDisplayValue(fields[k]);
    log('  ' + fields[k] + ' = ' + (dv === '' || dv === null ? '(empty)' : dv));
  }
}

log('');
log('Resolved references: owner=' + owner.label + ', manager=' + manager.label +
    ', supportGroup=' + supportGroup.label + ', department=' + department.label +
    ', location=' + location.label + ', company=' + company.label +
    ', costCentre=' + costCentre.label);

gs.info('\n' + report.join('\n'));
