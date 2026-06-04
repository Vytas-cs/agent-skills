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

  while (queue.length > 0 && results.length < maxFiles) {
    const { dir, depth } = queue.shift();
    if (depth > maxDepth) continue;

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
          if (results.length >= maxFiles) break;
        }
      }
    }
  }

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

function scanMalwarePatterns(wpRoot, { maxFilesScanned = 4000 } = {}) {
  const hits = [];
  const phpFiles = findFilesRecursive(
    wpRoot,
    (name) => SUSPICIOUS_PHP_EXTS.has(path.extname(name).toLowerCase()),
    { maxFiles: maxFilesScanned }
  );

  for (const file of phpFiles) {
    const content = readFileSafe(file, 256 * 1024);
    if (!content) continue;
    for (const pattern of MALWARE_PATTERNS) {
      if (pattern.regex.test(content)) {
        hits.push({ file, pattern: pattern.name });
      }
    }
  }

  return { filesScanned: phpFiles.length, hits };
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

function main() {
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
        note: "Heuristic regex match — investigate each file before deletion.",
      },
      recent_core_modifications: {
        days_window: 30,
        files: recentCore.slice(0, 50),
        count: recentCore.length,
        severity: recentCore.length > 0 ? "high" : "none",
        note: "Core .php files in wp-admin/wp-includes should match release timestamps. Recent unexpected mtimes are a red flag.",
      },
    },
  };

  const anyHigh = Object.values(report.signals).some((s) => s.severity === "high");
  const anyReview = Object.values(report.signals).some((s) => s.severity === "review");
  report.summary = {
    overall_severity: anyHigh ? "high" : anyReview ? "review" : "none",
    recommended_next_step: anyHigh
      ? "Proceed with full investigation per skill step 3. Treat as confirmed compromise."
      : anyReview
        ? "Manually inspect 'review' signals before declaring clean."
        : "No high-confidence indicators found. Compromise still possible via paths this scan does not cover (cloaked SEO spam, DB-only injections, host-level). Consider an external scanner.",
  };

  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
}

main();
