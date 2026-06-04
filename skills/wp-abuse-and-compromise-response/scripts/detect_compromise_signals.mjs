import fs from "node:fs";
import path from "node:path";

const DEFAULT_IGNORES = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
]);

const SUSPICIOUS_PHP_EXTS = new Set([
  ".php",
  ".phtml",
  ".phar",
  ".php3",
  ".php4",
  ".php5",
  ".php7",
  ".pht",
]);

const MALWARE_PATTERNS = [
  { name: "eval_gzinflate_base64", regex: /eval\s*\(\s*gzinflate\s*\(\s*base64_decode/i },
  { name: "eval_base64_decode",    regex: /eval\s*\(\s*base64_decode/i },
  { name: "eval_request_param",    regex: /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)/i },
  { name: "assert_request_param",  regex: /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i },
  { name: "exec_request_param",    regex: /(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_/i },
  { name: "preg_replace_e_modifier", regex: /preg_replace\s*\(\s*['"][^'"]*\/e['"]/i },
];

const KNOWN_MALWARE_FILENAMES = new Set([
  "wp-vcd.php",
  "wp-tmp.php",
  "wp-feed.php",
  "c99.php",
  "r57.php",
  "wso.php",
  "b374k.php",
]);

const WP_FLAVORED_DIR_BAIT = [
  /^wp-config-php$/,
  /^wp-content-update$/,
  /^wp-includes-update$/,
  /^wordpress-update$/,
  /^akismet-update$/,
];

function statSafe(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

function readFileSafe(p, maxBytes = 128 * 1024) {
  try {
    const buf = fs.readFileSync(p);
    if (buf.byteLength > maxBytes) return buf.subarray(0, maxBytes).toString("utf8");
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

function findFilesRecursive(rootDir, predicate, { maxFiles = 6000, maxDepth = 12 } = {}) {
  const results = [];
  const queue = [{ dir: rootDir, depth: 0 }];
  let truncated = false;
  let depthCapped = false;

  while (queue.length > 0 && results.length < maxFiles) {
    const { dir, depth } = queue.shift();
    if (depth > maxDepth) { depthCapped = true; continue; }

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const ent of entries) {
      const fullPath = path.join(dir, ent.name);

      if (ent.isDirectory()) {
        if (DEFAULT_IGNORES.has(ent.name)) continue;
        queue.push({ dir: fullPath, depth: depth + 1 });
      } else if (ent.isFile()) {
        if (predicate(ent.name, fullPath)) {
          results.push(fullPath);
          if (results.length >= maxFiles) {
            truncated = true;
            break;
          }
        }
      }
    }
  }

  if (queue.length > 0 && results.length >= maxFiles) truncated = true;

  results.truncated = truncated;
  results.depthCapped = depthCapped;
  return results;
}

function detectWpRoot(repoRoot) {
  const candidates = [
    repoRoot,
    path.join(repoRoot, "wordpress"),
    path.join(repoRoot, "wp"),
    path.join(repoRoot, "public"),
    path.join(repoRoot, "public_html"),
  ];
  for (const c of candidates) {
    if (statSafe(path.join(c, "wp-includes"))) return c;
  }
  return null;
}

function scanPhpInUploads(wpRoot) {
  const uploadsDir = path.join(wpRoot, "wp-content", "uploads");
  if (!statSafe(uploadsDir)) return [];
  return findFilesRecursive(uploadsDir, (name) => {
    const ext = path.extname(name).toLowerCase();
    return SUSPICIOUS_PHP_EXTS.has(ext);
  }, { maxFiles: 500 });
}

function scanMuPlugins(wpRoot) {
  const muDir = path.join(wpRoot, "wp-content", "mu-plugins");
  if (!statSafe(muDir)) return { exists: false, entries: [] };
  let entries = [];
  try {
    entries = fs.readdirSync(muDir);
  } catch {
    return { exists: true, entries: [] };
  }
  return { exists: true, entries };
}

function scanDropIns(wpRoot) {
  // Drop-ins live directly in wp-content/ (no wp-content/drop-ins/ subdirectory exists in stock WP).
  // Reference: https://developer.wordpress.org/reference/functions/_get_dropins/
  const wpContent = path.join(wpRoot, "wp-content");
  const knownDropIns = new Set([
    "advanced-cache.php",
    "db.php",
    "db-error.php",
    "install.php",
    "maintenance.php",
    "object-cache.php",
    "php-error.php",
    "fatal-error-handler.php",
    // Multisite-only
    "sunrise.php",
    "blog-deleted.php",
    "blog-inactive.php",
    "blog-suspended.php",
  ]);
  let present = [];
  try {
    const wpContentEntries = fs.readdirSync(wpContent);
    present = wpContentEntries.filter((n) => knownDropIns.has(n));
  } catch {
    // ignore
  }
  return { present };
}

function scanWpFlavoredBaitDirs(wpRoot) {
  const pluginsDir = path.join(wpRoot, "wp-content", "plugins");
  if (!statSafe(pluginsDir)) return [];
  let entries = [];
  try {
    entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isDirectory())
    .filter((e) => WP_FLAVORED_DIR_BAIT.some((rx) => rx.test(e.name)))
    .map((e) => e.name);
}

function scanKnownMalwareFilenames(wpRoot) {
  return findFilesRecursive(wpRoot, (name) => KNOWN_MALWARE_FILENAMES.has(name.toLowerCase()), { maxFiles: 50 });
}

function scanMalwarePatterns(wpRoot, { maxFilesScanned = 4000, maxFileBytes = 256 * 1024 } = {}) {
  const hits = [];
  const phpFiles = findFilesRecursive(
    wpRoot,
    (name) => SUSPICIOUS_PHP_EXTS.has(path.extname(name).toLowerCase()),
    { maxFiles: maxFilesScanned }
  );

  let filesReadTruncated = 0;
  for (const file of phpFiles) {
    const st = statSafe(file);
    if (st && st.size > maxFileBytes) filesReadTruncated += 1;
    const content = readFileSafe(file, maxFileBytes);
    if (!content) continue;
    for (const pattern of MALWARE_PATTERNS) {
      if (pattern.regex.test(content)) {
        hits.push({ file, pattern: pattern.name });
      }
    }
  }

  return {
    filesScanned: phpFiles.length,
    hits,
    fileListTruncated: phpFiles.truncated === true,
    depthCapped: phpFiles.depthCapped === true,
    filesReadTruncated,  // count of files where only the first maxFileBytes were scanned
    maxFilesScanned,
    maxFileBytes,
  };
}

function scanRecentCoreModifications(wpRoot, days = 30) {
  const cutoffMs = Date.now() - days * 24 * 60 * 60 * 1000;
  const coreDirs = ["wp-admin", "wp-includes"].map((d) => path.join(wpRoot, d));
  const recent = [];
  for (const dir of coreDirs) {
    if (!statSafe(dir)) continue;
    const files = findFilesRecursive(
      dir,
      (name) => name.endsWith(".php"),
      { maxFiles: 5000 }
    );
    for (const f of files) {
      const st = statSafe(f);
      if (st && st.mtimeMs > cutoffMs) {
        recent.push({ file: f, mtime: new Date(st.mtimeMs).toISOString() });
      }
    }
  }
  return recent;
}

// ---------------------------------------------------------------------------
// Vulnerability lookup (optional, only when --check-vulns is passed)
// ---------------------------------------------------------------------------
//
// Queries the wpvulnerability.com API (free, no API key required). The service
// aggregates vulnerability data from WPScan, Patchstack, and WP.org sources.
// Reference: https://www.wpvulnerability.com/
//
// Swappable: if you'd rather use WPScan or Patchstack directly, replace the
// VULN_API_BASE constant and the response-shape adapters below.

const VULN_API_BASE = "https://www.wpvulnerability.com/api/v3";
const VULN_FETCH_TIMEOUT_MS = 5000;
const VULN_CONCURRENCY = 5;

function detectWpCoreVersion(wpRoot) {
  const versionFile = path.join(wpRoot, "wp-includes", "version.php");
  const content = readFileSafe(versionFile);
  if (!content) return null;
  const m = content.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/);
  return m ? m[1] : null;
}

function parseWpPluginHeader(filePath) {
  const content = readFileSafe(filePath, 16 * 1024);
  if (!content) return null;
  const nameMatch = content.match(/^[\s*]*Plugin Name:\s*(.+)$/im);
  if (!nameMatch) return null;
  const versionMatch = content.match(/^[\s*]*Version:\s*(.+)$/im);
  return {
    name: nameMatch[1].trim(),
    version: versionMatch ? versionMatch[1].trim() : null,
  };
}

function detectInstalledPlugins(wpRoot) {
  const pluginsDir = path.join(wpRoot, "wp-content", "plugins");
  if (!statSafe(pluginsDir)) return [];
  const plugins = [];
  let entries;
  try {
    entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const slug = ent.name;
    const pluginDir = path.join(pluginsDir, slug);
    // The main plugin file is usually <slug>.php; fall back to scanning .php files in the root
    const candidates = [path.join(pluginDir, `${slug}.php`)];
    try {
      const dirEntries = fs.readdirSync(pluginDir);
      for (const f of dirEntries) {
        if (f.endsWith(".php") && !candidates.includes(path.join(pluginDir, f))) {
          candidates.push(path.join(pluginDir, f));
        }
      }
    } catch { /* ignore */ }
    for (const candidate of candidates) {
      const header = parseWpPluginHeader(candidate);
      if (header) {
        plugins.push({ slug, name: header.name, version: header.version });
        break;
      }
    }
  }
  return plugins;
}

function parseWpThemeHeader(styleCssPath) {
  const content = readFileSafe(styleCssPath, 8 * 1024);
  if (!content) return null;
  const nameMatch = content.match(/^[\s\/*]*Theme Name:\s*(.+)$/im);
  if (!nameMatch) return null;
  const versionMatch = content.match(/^[\s\/*]*Version:\s*(.+)$/im);
  return {
    name: nameMatch[1].trim(),
    version: versionMatch ? versionMatch[1].trim() : null,
  };
}

function detectInstalledThemes(wpRoot) {
  const themesDir = path.join(wpRoot, "wp-content", "themes");
  if (!statSafe(themesDir)) return [];
  const themes = [];
  let entries;
  try {
    entries = fs.readdirSync(themesDir, { withFileTypes: true });
  } catch {
    return [];
  }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const slug = ent.name;
    const styleCss = path.join(themesDir, slug, "style.css");
    const header = parseWpThemeHeader(styleCss);
    if (header) {
      themes.push({ slug, name: header.name, version: header.version });
    }
  }
  return themes;
}

async function fetchJsonWithTimeout(url, timeoutMs = VULN_FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { "User-Agent": "wp-abuse-detect-script/1" } });
    if (!res.ok) return { error: `HTTP ${res.status}`, url };
    const data = await res.json();
    return { data, url };
  } catch (e) {
    return { error: String(e?.message || e), url };
  } finally {
    clearTimeout(t);
  }
}

function compareVersions(a, b) {
  // Returns negative if a<b, 0 if equal, positive if a>b. Handles X.Y.Z and pre-release suffixes loosely.
  const pa = String(a).split(/[.+-]/).map((p) => parseInt(p, 10));
  const pb = String(b).split(/[.+-]/).map((p) => parseInt(p, 10));
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const x = isNaN(pa[i]) ? 0 : pa[i];
    const y = isNaN(pb[i]) ? 0 : pb[i];
    if (x !== y) return x - y;
  }
  return 0;
}

function vulnAffectsInstalledVersion(vuln, installedVersion) {
  if (!installedVersion) return { affected: null, reason: "version_unknown" };
  // wpvulnerability.com vuln records vary in shape; check operator-style fields, fallback to "patched_in"
  const ops = vuln?.operator || vuln?.affected || null;
  if (Array.isArray(ops)) {
    for (const op of ops) {
      const v = op?.version;
      const operator = op?.operator;
      if (!v || !operator) continue;
      const cmp = compareVersions(installedVersion, v);
      if (operator === "<=" && cmp <= 0) return { affected: true };
      if (operator === "<" && cmp < 0) return { affected: true };
      if (operator === "=" && cmp === 0) return { affected: true };
      if (operator === ">=" && cmp >= 0) return { affected: true };
      if (operator === ">" && cmp > 0) return { affected: true };
    }
    return { affected: false };
  }
  const patchedIn = vuln?.patched_in || vuln?.fixed_in;
  if (patchedIn) return { affected: compareVersions(installedVersion, patchedIn) < 0 };
  return { affected: null, reason: "no_version_constraints_in_record" };
}

function flattenVulnRecords(apiResult, installedVersion) {
  // wpvulnerability.com response shape varies; this code is best-effort and may need adjustment.
  if (!apiResult?.data) return { error: apiResult?.error, vulns: [], unknown_match: [] };
  const candidates = apiResult.data?.vulnerabilities || apiResult.data?.vulns || [];
  const matched = [];
  const unknownMatch = [];  // records where we couldn't determine if the installed version is affected
  for (const v of candidates) {
    const { affected, reason } = vulnAffectsInstalledVersion(v, installedVersion);
    const record = {
      id: v.id || v.cve || v.title?.slice(0, 40) || "unknown",
      title: v.title || v.summary || null,
      source: v.source || null,
      severity: v.severity || v.cvss?.severity || null,
      score: v.cvss?.score || null,
      patched_in: v.patched_in || v.fixed_in || null,
      url: v.source_url || v.url || null,
    };
    if (affected === true) {
      matched.push(record);
    } else if (affected === null) {
      unknownMatch.push({ ...record, match_uncertainty_reason: reason });
    }
  }
  return { vulns: matched, unknown_match: unknownMatch };
}

async function runWithConcurrency(items, worker, concurrency = VULN_CONCURRENCY) {
  const results = [];
  let i = 0;
  const lanes = Array(Math.min(concurrency, items.length)).fill(0).map(async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await worker(items[idx]);
    }
  });
  await Promise.all(lanes);
  return results;
}

async function checkVulnerabilities(wpRoot) {
  const wpVersion = detectWpCoreVersion(wpRoot);
  const plugins = detectInstalledPlugins(wpRoot);
  const themes = detectInstalledThemes(wpRoot);

  const corePromise = wpVersion
    ? fetchJsonWithTimeout(`${VULN_API_BASE}/wordpress/${encodeURIComponent(wpVersion)}`)
    : Promise.resolve({ error: "wp version not detected" });

  const pluginResults = await runWithConcurrency(plugins, async (p) => {
    const apiResult = await fetchJsonWithTimeout(`${VULN_API_BASE}/plugin/${encodeURIComponent(p.slug)}`);
    const { vulns, unknown_match, error } = flattenVulnRecords(apiResult, p.version);
    return {
      slug: p.slug,
      name: p.name,
      installed_version: p.version,
      vulnerabilities: vulns,
      vulnerabilities_uncertain_match: unknown_match,
      fetch_error: error || apiResult?.error,
    };
  });

  const themeResults = await runWithConcurrency(themes, async (t) => {
    const apiResult = await fetchJsonWithTimeout(`${VULN_API_BASE}/theme/${encodeURIComponent(t.slug)}`);
    const { vulns, unknown_match, error } = flattenVulnRecords(apiResult, t.version);
    return {
      slug: t.slug,
      name: t.name,
      installed_version: t.version,
      vulnerabilities: vulns,
      vulnerabilities_uncertain_match: unknown_match,
      fetch_error: error || apiResult?.error,
    };
  });

  const coreApi = await corePromise;
  const core = wpVersion ? flattenVulnRecords(coreApi, wpVersion) : { vulns: [], unknown_match: [] };

  const pluginsWithVulns = pluginResults.filter((p) => p.vulnerabilities.length > 0);
  const themesWithVulns = themeResults.filter((t) => t.vulnerabilities.length > 0);

  return {
    experimental: true,
    privacy_note: "This check sends a list of your installed plugin/theme slugs (not versions or contents) to wpvulnerability.com. On a compromised box, that inventory may be sensitive — do not run --check-vulns from a network you don't want the request traffic associated with. Skip this flag if in doubt.",
    source: "wpvulnerability.com (aggregates WPScan, Patchstack, WP.org). Response shape varies — adapter is best-effort.",
    wp_core: {
      installed_version: wpVersion,
      vulnerabilities: core.vulns,
      vulnerabilities_uncertain_match: core.unknown_match,
      fetch_error: coreApi?.error || null,
    },
    plugins: {
      total_checked: pluginResults.length,
      with_vulnerabilities: pluginsWithVulns,
      clean: pluginResults.length - pluginsWithVulns.length,
    },
    themes: {
      total_checked: themeResults.length,
      with_vulnerabilities: themesWithVulns,
      clean: themeResults.length - themesWithVulns.length,
    },
    severity: (core.vulns.length || pluginsWithVulns.length || themesWithVulns.length) > 0 ? "high" : "none",
    note: "Known vulnerabilities affecting installed versions. Patch immediately; if exploitation predates patching, this is the likely entry point. Records under 'vulnerabilities_uncertain_match' could not be confirmed as affecting your version — manually verify each.",
  };
}

async function main() {
  const args = process.argv.slice(2);
  const checkVulns = args.includes("--check-vulns");
  const repoRoot = process.cwd();
  const wpRoot = detectWpRoot(repoRoot);

  if (!wpRoot) {
    process.stdout.write(JSON.stringify({
      tool: { name: "detect_compromise_signals", version: 1 },
      project: { wpRootFound: false, repoRoot },
      message: "No WordPress install detected (no wp-includes/ found). Run skills/wp-project-triage/scripts/detect_wp_project.mjs first.",
    }, null, 2) + "\n");
    return;
  }

  const phpInUploads = scanPhpInUploads(wpRoot);
  const muPlugins = scanMuPlugins(wpRoot);
  const dropIns = scanDropIns(wpRoot);
  const baitDirs = scanWpFlavoredBaitDirs(wpRoot);
  const knownMalwareFiles = scanKnownMalwareFilenames(wpRoot);
  const patternScan = scanMalwarePatterns(wpRoot);
  const recentCore = scanRecentCoreModifications(wpRoot);
  const vulnReport = checkVulns ? await checkVulnerabilities(wpRoot) : null;

  const report = {
    tool: { name: "detect_compromise_signals", version: 1 },
    project: { wpRoot, repoRoot },
    signals: {
      php_in_uploads: {
        count: phpInUploads.length,
        files: phpInUploads.slice(0, 50),
        severity: phpInUploads.length > 0 ? "high" : "none",
        note: "PHP files inside wp-content/uploads/ are never legitimate.",
      },
      mu_plugins: {
        exists: muPlugins.exists,
        entries: muPlugins.entries,
        severity: muPlugins.exists && muPlugins.entries.length > 0 ? "review" : "none",
        note: "Auto-loaded; commonly missed during cleanup. Review every entry.",
      },
      drop_ins: {
        present_in_wp_content: dropIns.present,
        severity: dropIns.present.length > 0 ? "review" : "none",
        note: "Drop-ins (object-cache.php, advanced-cache.php, db.php, etc.) auto-load from wp-content/. Verify each is legitimate (caching plugin, hosting provider, etc.).",
      },
      wp_flavored_bait_directories: {
        directories: baitDirs,
        severity: baitDirs.length > 0 ? "high" : "none",
        note: "Plugin directories with WP-mimicking names are a known compromise pattern.",
      },
      known_malware_filenames: {
        files: knownMalwareFiles,
        severity: knownMalwareFiles.length > 0 ? "high" : "none",
        note: "Known web shell / malware-family file names.",
      },
      malware_pattern_hits: {
        files_scanned: patternScan.filesScanned,
        hits: patternScan.hits.slice(0, 200),
        hit_count: patternScan.hits.length,
        severity: patternScan.hits.length > 0 ? "high" : "none",
        file_list_truncated: patternScan.fileListTruncated,
        files_read_truncated: patternScan.filesReadTruncated,
        depth_capped: patternScan.depthCapped,
        note: patternScan.fileListTruncated || patternScan.filesReadTruncated > 0 || patternScan.depthCapped
          ? `SCAN TRUNCATED — file list capped at ${patternScan.maxFilesScanned}, file bodies capped at ${patternScan.maxFileBytes} bytes. A zero hit count does NOT mean clean. Run wp core verify-checksums + wp plugin verify-checksums --all and a full external scanner.`
          : "Heuristic regex match — investigate each file before deletion.",
      },
      recent_core_modifications: {
        days_window: 30,
        files: recentCore.slice(0, 50),
        count: recentCore.length,
        severity: recentCore.length > 0 ? "review" : "none",
        note: "Recent mtime in wp-admin/wp-includes can mean either (a) a legitimate WP core update or (b) tampering. Mtimes reflect extraction/download time, not release date. Use wp core verify-checksums to distinguish — only checksum mismatches are evidence of tampering.",
      },
    },
  };

  if (vulnReport) {
    report.signals.known_vulnerabilities = vulnReport;
  }

  const anyHigh = Object.values(report.signals).some((s) => s.severity === "high");
  const anyReview = Object.values(report.signals).some((s) => s.severity === "review");
  const scanTruncated = report.signals.malware_pattern_hits.file_list_truncated
    || report.signals.malware_pattern_hits.files_read_truncated > 0
    || report.signals.malware_pattern_hits.depth_capped;

  let overall, next;
  if (anyHigh) {
    overall = "high";
    next = "Multiple high-confidence indicators present. Proceed with full investigation per skill step 3 — but DO NOT skip the manual checks: this scan covers a subset of compromise patterns, not all.";
  } else if (anyReview || scanTruncated) {
    overall = "review";
    next = scanTruncated
      ? "Scan was TRUNCATED (large site exceeded scan caps). A zero hit count is NOT evidence of clean. Run wp core verify-checksums, wp plugin verify-checksums --all, and a full external scanner (Sucuri, Wordfence, MalCare) before declaring clean."
      : "Manually inspect 'review' signals before declaring clean.";
  } else {
    overall = "none";
    next = "No high-confidence indicators in this scan. Compromise still possible via paths this scan does not cover (cloaked SEO spam, DB-only injections, host-level, files past size cap). Consider an external scanner.";
  }

  report.summary = {
    overall_severity: overall,
    scan_truncated: scanTruncated,
    recommended_next_step: next,
  };

  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
}

main().catch((err) => {
  process.stderr.write(`detect_compromise_signals failed: ${err?.stack || err}\n`);
  process.exit(1);
});
