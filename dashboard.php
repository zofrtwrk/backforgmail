<?php
/**************************
 * Email Validation Dashboard
 * - numbered rows
 * - totals & unique counts
 * - pagination support (?page=1&per=50)
 * - resilient JSON parsing
 **************************/

$LOG_FILE = __DIR__ . '/.data/validated.log';

/* ---------- load & decode ---------- */
$lines = file_exists($LOG_FILE)
  ? array_reverse(file($LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES))
  : [];

$rows = [];
foreach ($lines as $line) {
  $j = json_decode($line, true);
  if (!is_array($j)) continue;
  // normalize fields so we don't get notices
  $rows[] = [
    'time' => $j['time'] ?? '',
    'email'=> $j['email'] ?? '',
    'ip'   => $j['ip'] ?? '',
    'ua'   => $j['ua'] ?? '',
  ];
}

$total = count($rows);
$uniqueEmails = count(array_unique(array_map(fn($r)=>strtolower($r['email']), $rows)));
$uniqueIPs    = count(array_unique(array_map(fn($r)=>$r['ip'], $rows)));

/* ---------- pagination ---------- */
$page = max(1, (int)($_GET['page'] ?? 1));
$per  = max(1, min(500, (int)($_GET['per'] ?? 100))); // default 100, cap 500
$start = ($page - 1) * $per;
$paginated = array_slice($rows, $start, $per);
$pages = max(1, (int)ceil($total / $per));

/* ---------- html ---------- */
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Email Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root{
    --bg:#f5f7fb; --card:#fff; --line:#e5e7eb; --head:#e3e8f7; --text:#111827; --muted:#6b7280; --accent:#10793F;
  }
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:32px;background:var(--bg);color:var(--text)}
  .wrap{max-width:1100px;margin:0 auto}
  h1{margin:0 0 8px 0;font-size:22px}
  .meta{color:var(--muted);font-size:13px;margin-bottom:16px}
  .stats{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0 18px}
  .chip{background:#fff;border:1px solid var(--line);padding:6px 10px;border-radius:999px;font-size:12px}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
  th,td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
  th{background:var(--head);text-align:left;font-weight:600}
  tr:last-child td{border-bottom:none}
  .num{width:64px;text-align:right;color:#374151}
  .time{white-space:nowrap}
  .email{font-weight:600}
  .ip{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px}
  .ua{color:var(--muted);font-size:12px}
  .toolbar{display:flex;justify-content:space-between;align-items:center;margin:10px 0}
  .pager{display:flex;gap:8px;align-items:center}
  .pager a,.pager span{padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:#fff;text-decoration:none;color:#111827;font-size:13px}
  .pager .active{background:var(--accent);border-color:var(--accent);color:#fff}
  .controls{font-size:13px;color:var(--muted)}
  .controls input{width:64px;padding:4px 6px;border:1px solid var(--line);border-radius:6px;margin-left:6px}
  .badge{display:inline-block;padding:2px 8px;border:1px solid var(--line);border-radius:999px;font-size:11px;background:#fff}
  @media (max-width:720px){
    .ua{display:none}
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>Validated e-mails</h1>
  <div class="meta">
    Generated: <?= htmlspecialchars((new DateTime('now'))->format('Y-m-d H:i:s T')) ?>
  </div>

  <div class="stats">
    <span class="chip">Total logs: <strong><?= number_format($total) ?></strong></span>
    <span class="chip">Unique emails: <strong><?= number_format($uniqueEmails) ?></strong></span>
    <span class="chip">Unique IPs: <strong><?= number_format($uniqueIPs) ?></strong></span>
    <span class="chip">Page: <strong><?= $page ?></strong> / <?= $pages ?></span>
    <span class="chip">Per page: <strong><?= $per ?></strong></span>
  </div>

  <div class="toolbar">
    <div class="controls">
      Show per page:
      <input type="number" min="1" max="500" value="<?= $per ?>" onchange="location.search='?per='+this.value+'&page=1'">
    </div>
    <div class="pager">
      <?php if ($page > 1): ?>
        <a href="?page=1&per=<?= $per ?>">« First</a>
        <a href="?page=<?= $page-1 ?>&per=<?= $per ?>">‹ Prev</a>
      <?php else: ?>
        <span>« First</span><span>‹ Prev</span>
      <?php endif; ?>
      <span class="active"><?= $page ?></span>
      <?php if ($page < $pages): ?>
        <a href="?page=<?= $page+1 ?>&per=<?= $per ?>">Next ›</a>
        <a href="?page=<?= $pages ?>&per=<?= $per ?>">Last »</a>
      <?php else: ?>
        <span>Next ›</span><span>Last »</span>
      <?php endif; ?>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th class="num">#</th>
        <th>Time</th>
        <th>Email</th>
        <th>IP</th>
        <th>User-Agent</th>
      </tr>
    </thead>
    <tbody>
      <?php
      if (!$paginated) {
        echo '<tr><td colspan="5" style="text-align:center;color:#6b7280;padding:24px">No records.</td></tr>';
      } else {
        foreach ($paginated as $k => $r) {
          // absolute row number (1-based across all pages, latest first)
          $abs = $start + $k + 1;

          $uaFull = $r['ua'] ?? '';
          $uaShort = mb_strlen($uaFull) > 60 ? mb_substr($uaFull, 0, 60) . '…' : $uaFull;

          printf(
            '<tr>
               <td class="num">%d</td>
               <td class="time">%s</td>
               <td class="email">%s</td>
               <td class="ip">%s</td>
               <td class="ua" title="%s">%s</td>
             </tr>',
            $abs,
            htmlspecialchars($r['time']),
            htmlspecialchars($r['email']),
            htmlspecialchars($r['ip']),
            htmlspecialchars($uaFull),
            htmlspecialchars($uaShort)
          );
        }
      }
      ?>
    </tbody>
  </table>

  <p class="meta" style="margin-top:12px">
    File: <span class="badge"><?= htmlspecialchars($LOG_FILE) ?></span>
  </p>

  <details style="margin-top:18px;color:#374151">
    <summary><strong>Seeing the same IP for every log?</strong></summary>
    <div style="margin-top:8px;font-size:14px;line-height:1.5">
      That usually means your logger records the reverse-proxy IP (e.g., Cloudflare) instead of the client IP.
      In your <em>logging script</em> (the one that writes <code>validated.log</code>), use this resolver:
      <pre style="background:#0b1220;color:#e5e7eb;padding:12px;border-radius:6px;overflow:auto"><code><?php
function getClientIpAccurate(): string {
  $keys = [
    'HTTP_CF_CONNECTING_IP',     // Cloudflare
    'HTTP_X_FORWARDED_FOR',      // Generic proxies (may be a list)
    'HTTP_X_REAL_IP',
    'HTTP_X_CLIENT_IP',
    'HTTP_X_FORWARDED',
    'HTTP_FORWARDED_FOR',
    'HTTP_FORWARDED',
    'REMOTE_ADDR',
  ];
  foreach ($keys as $key) {
    if (!empty($_SERVER[$key])) {
      $val = trim((string)$_SERVER[$key]);
      // X-Forwarded-For could be "client, proxy1, proxy2" — take the first public IP
      if ($key === 'HTTP_X_FORWARDED_FOR') {
        foreach (explode(',', $val) as $cand) {
          $cand = trim($cand);
          if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $cand;
          }
        }
        // fallback: first item as-is
        $first = trim(explode(',', $val)[0]);
        if ($first) return $first;
      }
      if (filter_var($val, FILTER_VALIDATE_IP)) return $val;
    }
  }
  return '0.0.0.0';
}
// Example usage when logging:
// $ip = getClientIpAccurate();
// fwrite($fh, json_encode(['time'=>gmdate('c'),'email'=>$email,'ip'=>$ip,'ua'=>$_SERVER['HTTP_USER_AGENT'] ?? ''])."\n");
?></code></pre>
    </div>
  </details>
</div>
</body>
</html>
