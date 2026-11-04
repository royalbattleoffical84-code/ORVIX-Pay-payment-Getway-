<?php
/**
 * FamPay via Gmail (auto-detect, no UTR typing) — based on fampay_gateway.py.
 * The merchant's FamPay payment e-mails land in HIS Gmail. The payer just pays by UPI; we read recent FamPay mails over IMAP
 * and match: sender domain + Gmail DKIM/SPF pass, exact amount, payment time after the order was created (and consistent
 * with Gmail's arrival time). Every mail (its UTR/ref id) can confirm only ONE order (payment_utrs).
 */
if (!defined('GMAIL_IMAP_HOST')) define('GMAIL_IMAP_HOST', 'imap.gmail.com');
if (!defined('GMAIL_IMAP_PORT')) define('GMAIL_IMAP_PORT', 993);
if (!defined('GMAIL_IMAP_TLS'))  define('GMAIL_IMAP_TLS', true);

function gm_cfg(): array {
    return ['sender_domains' => ['famapp.in', 'famapp.com', 'fampay.in', 'famapp.co'], 'require_auth' => true,
            'lookback_days' => 3, 'max_fetch' => 10, 'max_mail_bytes' => 3000000, 'timeout' => 15,
            'order_window' => ORDER_EXPIRY_MIN * 60, 'late_utr_window' => 86400, 'clock_skew' => 300, 'max_payment_age' => 7200,
            'email_max_delay' => 3600, 'verify_max_age' => 21600, 'max_utr_tries' => 5];
}

/* ------------------------------------------------------------------ Render IMAP bridge */
function gm_bridge_request(string $path, array $payload): array {
    $base = rtrim((string)(getenv('ORVIX_IMAP_API_URL') ?: (defined('ORVIX_IMAP_API_URL') ? ORVIX_IMAP_API_URL : '')), '/');
    $key = (string)(getenv('ORVIX_IMAP_API_KEY') ?: (defined('ORVIX_IMAP_API_KEY') ? ORVIX_IMAP_API_KEY : ''));
    if ($base === '' || $key === '' || !function_exists('curl_init')) return ['ok'=>false,'error'=>'bridge_not_configured'];
    $ch = curl_init($base . $path);
    curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_RETURNTRANSFER=>true, CURLOPT_CONNECTTIMEOUT=>8, CURLOPT_TIMEOUT=>35,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json','Authorization: Bearer '.$key],
        CURLOPT_POSTFIELDS=>json_encode($payload)]);
    $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    $data = is_string($body) ? json_decode($body, true) : null;
    return is_array($data) && $code >= 200 && $code < 300 ? $data : ['ok'=>false,'error'=>($data['error'] ?? 'bridge_unavailable')];
}
function gm_bridge_payload(array $m): ?array {
    $pass = gm_decrypt($m['gm_pass'] ?? '');
    if ($pass === null || empty($m['gm_email'])) return null;
    return ['email'=>(string)$m['gm_email'],'appPassword'=>$pass];
}
/* ------------------------------------------------------------------ credential encryption */
function gm_key(): string { return hash('sha256', 'orvix-gm|' . DB_PASS . '|' . FAMAPI_KEY, true); }
function gm_encrypt(string $plain): string {
    $iv = random_bytes(12); $tag = '';
    $c = openssl_encrypt($plain, 'aes-256-gcm', gm_key(), OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $c);
}
function gm_decrypt(?string $blob): ?string {
    $raw = base64_decode((string)$blob, true); if ($raw === false || strlen($raw) < 29) return null;
    $p = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', gm_key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $p === false ? null : $p;
}
function gm_unlocked(array $m): bool { return !empty($m['gm_unlocked']) || (float)setting_num('gm_unlock_fee') <= 0; }
function gm_ready(array $m): bool { return !empty($m['gm_ok']) && !empty($m['gm_email']) && !empty($m['gm_upi']) && !empty($m['gm_pass']); }
function gm_mode(array $m): bool { return ($m['pay_mode'] ?? 'famapi') === 'gmail' && gm_ready($m) && gm_unlocked($m); }

/* ------------------------------------------------------------------ UTR helpers */
function gm_normalize_utr($raw): ?string {
    if ($raw === null) return null;
    $s = trim((string)$raw);
    $s = preg_replace('/^(?:fam\s*pay|fam\s*app|fam|utr|upi\s*ref|upi\s*txn|txn|transaction|ref)[\s\-_]*(?:transaction|txn|upi|ref)?[\s\-_]*(?:id|no|number|num)?\.?\s*[:#\-]\s*/i', '', $s);
    $s = preg_replace('/^utr\s+(?:(?:id|no|number|num)\.?\s+)?/i', '', $s);
    $s = preg_replace('/^(?:fam\s*pay\s*|fam\s*app\s*)?(?:transaction|txn|upi\s*ref(?:erence)?|ref(?:erence)?)\s*(?:id|no|number|num)\.?\s+/i', '', $s);
    $s = strtoupper(preg_replace('/[\s\-_]/', '', $s));
    $s = preg_replace('/^UTR(?=\d{8,})/', '', $s);
    if (!preg_match('/^[A-Z0-9]{8,40}$/', $s) || !preg_match('/\d/', $s)) return null;
    return preg_match('/^FMPIB(\d{6,14})$/', $s, $mm) ? $mm[1] : $s;
}
function gm_utr_aliases(string $utr): array {
    $u = strtoupper(trim($utr)); $out = [$u];
    if (preg_match('/^FMPIB(\d{6,14})$/', $u, $m)) $out[] = $m[1];
    elseif (preg_match('/^\d{6,14}$/', $u)) $out[] = 'FMPIB' . $u;
    return $out;
}

/* ------------------------------------------------------------------ MIME parsing */
function gm_parse_headers(string $block): array {
    $block = preg_replace('/\r?\n[ \t]+/', ' ', $block); $h = [];
    foreach (preg_split('/\r?\n/', $block) as $line) {
        if (!preg_match('/^([!-9;-~]+):\s*(.*)$/', $line, $m)) continue;
        $h[strtolower($m[1])][] = $m[2];
    }
    return $h;
}
function gm_decode_header(string $v): string {
    $r = @iconv_mime_decode($v, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8'); return $r === false ? $v : $r;
}
function gm_param(string $hv, string $name): ?string {
    if (preg_match('/;\s*' . $name . '\s*=\s*(?:"([^"]*)"|([^;\s]+))/i', $hv, $m)) return $m[1] !== '' ? $m[1] : ($m[2] ?? null);
    return null;
}
/** Returns ['headers'=>[], 'text'=>string] — text = all text/plain + text/html(→text) parts. */
function gm_parse_mail(string $raw, int $depth = 0): array {
    $sep = preg_match('/\r?\n\r?\n/', $raw, $mm, PREG_OFFSET_CAPTURE) ? $mm[0][1] : strlen($raw);
    $hdr = gm_parse_headers(substr($raw, 0, $sep)); $body = substr($raw, $sep + (isset($mm[0]) ? strlen($mm[0][0]) : 0));
    $ct = $hdr['content-type'][0] ?? 'text/plain'; $type = strtolower(trim(explode(';', $ct)[0]));
    $text = '';
    if (strpos($type, 'multipart/') === 0 && $depth < 6 && ($b = gm_param($ct, 'boundary'))) {
        foreach (explode('--' . $b, $body) as $i => $part) {
            if ($i === 0 || strpos(ltrim($part), '--') === 0) continue;
            $text .= "\n" . gm_parse_mail(ltrim($part, "\r\n"), $depth + 1)['text'];
        }
    } elseif (in_array($type, ['text/plain', 'text/html'], true) && stripos($hdr['content-disposition'][0] ?? '', 'attachment') === false) {
        $enc = strtolower(trim($hdr['content-transfer-encoding'][0] ?? '7bit'));
        if ($enc === 'base64') $body = (string)base64_decode($body); elseif ($enc === 'quoted-printable') $body = quoted_printable_decode($body);
        $cs = strtolower(gm_param($ct, 'charset') ?? 'utf-8');
        if ($cs !== 'utf-8' && $cs !== 'us-ascii') { $c = @mb_convert_encoding($body, 'UTF-8', $cs); if ($c !== false) $body = $c; }
        $text = $type === 'text/html' ? gm_html_to_text($body) : $body;
    }
    return ['headers' => $hdr, 'text' => $text];
}
function gm_html_to_text(string $h): string {
    $h = preg_replace('/<(script|style).*?<\/\1>/is', ' ', $h);
    $h = preg_replace('/<br\s*\/?>|<\/p>|<\/tr>|<\/div>|<\/li>/i', "\n", $h);
    $h = preg_replace('/<\/t[dh]>/i', ' ', $h);
    return html_entity_decode(preg_replace('/<[^>]+>/', ' ', $h), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
function gm_clean_text(string $t): string { return substr(preg_replace('/[ \t\r\f\v]+/', ' ', str_replace("\xC2\xA0", ' ', $t)), 0, 200000); }

/* ------------------------------------------------------------------ amount / utr / time parsing */
function gm_to_paise(string $s): ?int {
    $s = str_replace(',', '', $s);
    if (!preg_match('/^(\d+)(?:\.(\d{1,2}))?$/', $s, $m)) return null;
    return (int)$m[1] * 100 + (isset($m[2]) ? (int)str_pad($m[2], 2, '0') : 0);
}
function gm_parse_amount_paise(string $text): ?int {
    $cur = '(?:₹|\brs\.?|\binr\b)'; $num = '([0-9][0-9,]*(?:\.[0-9]{1,2})?)';
    $keyed = [];
    foreach (['/(?:received|credited|credit|payment\s+of|paid|deposited|amount)[^0-9₹\n]{0,40}?' . $cur . '\s*' . $num . '/iu',
              '/' . $cur . '\s*' . $num . '\s*(?:has\s+been\s+|was\s+)?(?:received|credited|paid)/iu'] as $rx) {
        if (preg_match_all($rx, $text, $mm)) foreach ($mm[1] as $v) if (($p = gm_to_paise($v)) !== null) $keyed[$p] = 1;
    }
    if (count($keyed) === 1) return (int)array_key_first($keyed);
    if (count($keyed) > 1) return null;
    $any = [];
    if (preg_match_all('/' . $cur . '\s*' . $num . '/iu', $text, $mm)) foreach ($mm[1] as $v) if (($p = gm_to_paise($v)) !== null) $any[$p] = 1;
    return count($any) === 1 ? (int)array_key_first($any) : null;
}
function gm_utr_in_text(string $text, string $utr): bool {
    $labeled = [];
    $rx = '/(?:\butr\b|upi\s*ref(?:erence)?(?:\s*(?:no|id|number))?|transaction\s*(?:id|no|number|ref(?:erence)?)|txn\s*(?:id|no|ref)|ref(?:erence)?\s*(?:id|no|number)|\brrn\b|fam\s*(?:pay|app)?\s*(?:transaction|txn|payment)?\s*(?:id|no|number)|payment\s*id|upi\s*(?:transaction|txn)\s*id)\s*[:#\-]?\s*(?:is\s*)?([A-Za-z0-9]{8,40})\b/i';
    if (preg_match_all($rx, $text, $mm)) foreach ($mm[1] as $v) $labeled[strtoupper($v)] = 1;
    $tokens = [];
    if (preg_match_all('/\b[A-Za-z0-9]{8,40}\b/', $text, $mm)) foreach ($mm[0] as $v) $tokens[strtoupper($v)] = 1;
    foreach (gm_utr_aliases($utr) as $u) {
        if (isset($labeled[$u])) return true;
        if (!$labeled) { if (isset($tokens[$u])) return true; }
        elseif (isset($tokens[$u]) && (preg_match('/^\d{10,12}$/', $u) || preg_match('/^(?:FMPIB[A-Z0-9]{4,35}|FAM[A-Z0-9]{9,35})$/i', $u))) return true;
    }
    return false;
}
function gm_months(): array { return ['jan' => 1, 'feb' => 2, 'mar' => 3, 'apr' => 4, 'may' => 5, 'jun' => 6, 'jul' => 7, 'aug' => 8, 'sep' => 9, 'oct' => 10, 'nov' => 11, 'dec' => 12]; }
/** All date+time values in the body, read as IST, returned as epoch seconds (UTC). */
function gm_body_datetimes(string $text): array {
    $mon = gm_months(); $out = [];
    $ap = '\s*([AaPp]\.?[Mm]\.?)?'; $tm = '(\d{1,2}):(\d{2})(?::(\d{2}))?';
    $pats = [
        ['ymd', '/(\d{4})-(\d{2})-(\d{2})[T ]' . $tm . $ap . '/'],
        ['dmy', '/(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{4}),?\s*(?:at\s*)?' . $tm . $ap . '/i'],
        ['dMy', '/(\d{1,2})(?:st|nd|rd|th)?\s+([A-Za-z]{3,9})\.?,?\s+(\d{4}),?\s*(?:at\s*|-\s*)?' . $tm . $ap . '/'],
        ['Mdy', '/([A-Za-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4}),?\s*(?:at\s*|-\s*)?' . $tm . $ap . '/'],
    ];
    foreach ($pats as [$kind, $rx]) {
        if (!preg_match_all($rx, $text, $all, PREG_SET_ORDER)) continue;
        foreach ($all as $g) {
            if ($kind === 'ymd') { $y = (int)$g[1]; $mo = (int)$g[2]; $d = (int)$g[3]; }
            elseif ($kind === 'dmy') { $d = (int)$g[1]; $mo = (int)$g[2]; $y = (int)$g[3]; }
            elseif ($kind === 'dMy') { $d = (int)$g[1]; $y = (int)$g[3]; $mo = $mon[strtolower(substr($g[2], 0, 3))] ?? 0; }
            else { $mo = $mon[strtolower(substr($g[1], 0, 3))] ?? 0; $d = (int)$g[2]; $y = (int)$g[3]; }
            if (!$mo || $mo > 12 || $d < 1 || $d > 31) continue;
            $h = (int)$g[4]; $mi = (int)$g[5]; $s = (int)($g[6] ?? 0); $a = $g[7] ?? '';
            if ($a !== '') { if ($h < 1 || $h > 12) continue; $p = strtolower(str_replace('.', '', $a)); if ($p === 'pm' && $h < 12) $h += 12; elseif ($p === 'am' && $h === 12) $h = 0; }
            if ($h > 23 || $mi > 59 || $s > 59) continue;
            $out[] = gmmktime($h, $mi, $s, $mo, $d, $y) - 19800;
        }
    }
    return $out;
}
function gm_domain_allowed(array $cfg, string $dom): bool {
    $dom = strtolower(trim($dom, '. '));
    foreach ($cfg['sender_domains'] as $d) if ($dom === $d || substr($dom, -strlen($d) - 1) === '.' . $d) return true;
    return false;
}
function gm_auth_ok(array $cfg, array $hdr): bool {
    if (!$cfg['require_auth']) return true;
    foreach ($hdr['authentication-results'] ?? [] as $h) {
        $hs = strtolower(preg_replace('/\s+/', ' ', $h));
        if (strpos($hs, 'mx.google.com') !== 0) continue;
        if (preg_match_all('/dkim=pass[^;]*?header\.(?:d|i)=@?([a-z0-9.\-]+)/', $hs, $mm)) foreach ($mm[1] as $d) if (gm_domain_allowed($cfg, $d)) return true;
        if (preg_match_all('/spf=pass[^;]*?smtp\.mailfrom=(?:[^@\s;]*@)?([a-z0-9.\-]+)/', $hs, $mm)) foreach ($mm[1] as $d) if (gm_domain_allowed($cfg, $d)) return true;
        return false;
    }
    return false;
}
function gm_internaldate(string $blob): ?int {
    if (!preg_match('/INTERNALDATE\s+"\s*(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\s*"/', $blob, $m)) return null;
    $mon = gm_months()[strtolower($m[2])] ?? null; if (!$mon) return null;
    $base = gmmktime((int)$m[4], (int)$m[5], (int)$m[6], $mon, (int)$m[1], (int)$m[3]);
    return $base - ($m[7] === '+' ? 1 : -1) * ((int)$m[8] * 3600 + (int)$m[9] * 60);
}
/** Never throws. Describes what the mail says; the verifier decides. */
function gm_parse_payment_email(array $cfg, string $raw, ?string $utr, ?int $arrival): array {
    $info = ['sender_ok' => false, 'utr_match' => false, 'ref' => null, 'amount_paise' => null, 'paid_at' => null, 'paid_src' => '', 'arrival_at' => $arrival, 'time_conflict' => false];
    try {
        $pm = gm_parse_mail($raw); $hdr = $pm['headers'];
        $from = gm_decode_header($hdr['from'][0] ?? '');
        $dom = preg_match('/@([A-Za-z0-9.\-]+)/', $from, $mm) ? strtolower($mm[1]) : '';
        $info['sender_ok'] = $dom !== '' && gm_domain_allowed($cfg, $dom) && gm_auth_ok($cfg, $hdr);
        $text = gm_clean_text($pm['text']);
        $info['utr_match'] = $utr !== null && gm_utr_in_text($text, $utr);
        $rx = '/(?:\butr\b|upi\s*ref(?:erence)?(?:\s*(?:no|id|number))?|transaction\s*(?:id|no|number)|txn\s*(?:id|no)|\brrn\b|payment\s*id)\s*[:#\-]?\s*(?:is\s*)?([A-Za-z0-9]{8,40})\b/i';
        $info['ref'] = preg_match($rx, $text, $rm) ? strtoupper($rm[1]) : 'MID' . strtoupper(substr(sha1(($hdr['message-id'][0] ?? '') . ($hdr['date'][0] ?? '') . $text), 0, 30));
        $info['amount_paise'] = gm_parse_amount_paise($text);
        $hdrTs = isset($hdr['date'][0]) ? (strtotime($hdr['date'][0]) ?: null) : null;
        $ref = $arrival ?? $hdrTs; $bt = gm_body_datetimes($text); $chosen = null; $src = '';
        if ($bt) {
            if ($ref !== null) foreach ($bt as $base) foreach ([$base, $base + 19800] as $cand) {
                $gap = $ref - $cand;
                if ($gap >= -$cfg['clock_skew'] && $gap <= $cfg['email_max_delay'] && ($chosen === null || abs($ref - $cand) < abs($ref - $chosen))) { $chosen = $cand; $src = 'body'; }
            }
            if ($chosen === null) $info['time_conflict'] = true;
        } elseif ($hdrTs !== null) {
            if ($ref !== null && $ref - $hdrTs > $cfg['email_max_delay']) $info['time_conflict'] = true; else { $chosen = $hdrTs; $src = 'header'; }
        } elseif ($arrival !== null) { $chosen = $arrival; $src = 'arrival'; }
        if ($chosen !== null) { $info['paid_at'] = (int)$chosen; $info['paid_src'] = $src; }
    } catch (Throwable $e) { error_log('ORVIX gm parse: ' . $e->getMessage()); }
    return $info;
}
function gm_check_payment_time(array $cfg, array $em, int $created, ?int $utrAt, int $now): array {
    $ts = $em['paid_at']; $arr = $em['arrival_at']; $src = $em['paid_src']; $skew = $cfg['clock_skew'];
    if ($ts === null) return [false, $em['time_conflict'] ? 'time_inconsistent' : 'time_unreadable'];
    if ($ts > $now + $skew || ($arr !== null && ($ts > $arr + $skew || $arr > $now + $skew))) return [false, 'future_timestamp'];
    if ($ts < $created - $skew) return [false, 'payment_before_order'];
    $maxAge = $src === 'body' ? $cfg['max_payment_age'] : min($cfg['max_payment_age'], $cfg['order_window'] + $cfg['email_max_delay']);
    if ($ts > $created + $maxAge) return [false, 'payment_too_late'];
    if ($utrAt && $ts > $utrAt + ($src === 'body' ? $skew : $cfg['email_max_delay'])) return [false, 'payment_after_utr_submit'];
    return [true, ''];
}

/* ------------------------------------------------------------------ minimal IMAP client */
class GmImap {
    private $fp; private int $n = 0;
    public function __construct(private array $cfg) {}
    public function connect(): void {
        $addr = (GMAIL_IMAP_TLS ? 'ssl' : 'tcp') . '://' . GMAIL_IMAP_HOST . ':' . GMAIL_IMAP_PORT;
        $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $this->fp = @stream_socket_client($addr, $en, $es, $this->cfg['timeout'], STREAM_CLIENT_CONNECT, $ctx);
        if (!$this->fp) throw new RuntimeException('connect: ' . ($es ?: 'blocked'), 1);
        stream_set_timeout($this->fp, $this->cfg['timeout']);
        $g = fgets($this->fp, 4096); if ($g === false || strpos($g, '* OK') !== 0) throw new RuntimeException('bad greeting', 1);
    }
    private static function q(string $s): string { return '"' . addcslashes($s, "\"\\") . '"'; }
    /** Returns ['ok'=>bool, 'items'=>[['head'=>string,'lit'=>?string]]]. */
    public function cmd(string $c): array {
        $tag = 'A' . (++$this->n);
        fwrite($this->fp, "$tag $c\r\n"); $items = [];
        while (true) {
            $line = fgets($this->fp, 65536);
            if ($line === false) throw new RuntimeException('connection lost', 1);
            if (strpos($line, $tag . ' ') === 0) return ['ok' => stripos($line, "$tag OK") === 0, 'line' => trim($line), 'items' => $items];
            $head = $line; $lit = null;
            while (preg_match('/\{(\d+)\}\r?\n$/', $head, $m)) {
                $len = (int)$m[1]; if ($len > $this->cfg['max_mail_bytes']) { $this->skip($len); $lit = null; }
                else { $lit = ''; while (strlen($lit) < $len) { $c2 = fread($this->fp, $len - strlen($lit)); if ($c2 === '' || $c2 === false) throw new RuntimeException('connection lost', 1); $lit .= $c2; } }
                $more = fgets($this->fp, 65536); if ($more === false) throw new RuntimeException('connection lost', 1);
                $head = $head . '' . $more;
                if (!preg_match('/\{(\d+)\}\r?\n$/', $more)) break;
            }
            $items[] = ['head' => $head, 'lit' => $lit];
        }
    }
    private function skip(int $len): void { while ($len > 0) { $c = fread($this->fp, min(8192, $len)); if ($c === '' || $c === false) break; $len -= strlen($c); } }
    public function login(string $u, string $p): bool { return $this->cmd('LOGIN ' . self::q($u) . ' ' . self::q($p))['ok']; }
    public function examine(string $box): bool { return $this->cmd('EXAMINE ' . self::q($box))['ok']; }
    public function recent(int $days): array {
        $r = $this->cmd('SEARCH X-GM-RAW ' . self::q('(from:famapp.in OR from:famapp.com OR from:fampay.in OR from:famapp.co) newer_than:' . $days . 'd'));
        if (!$r['ok']) $r = $this->cmd('SEARCH SINCE ' . gmdate('d-M-Y', time() - $days * 86400));
        $ids = [];
        if ($r['ok']) foreach ($r['items'] as $it) if (preg_match('/^\* SEARCH\s*([\d ]*)/', $it['head'], $m)) foreach (preg_split('/\s+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY) as $i) $ids[] = (int)$i;
        return $ids;
    }
    public function search(string $utr, int $days): array {
        $r = $this->cmd('SEARCH X-GM-RAW ' . self::q('"' . $utr . '" newer_than:' . $days . 'd'));
        if (!$r['ok']) $r = $this->cmd('SEARCH SINCE ' . gmdate('d-M-Y', time() - $days * 86400) . ' TEXT ' . self::q($utr));
        $ids = [];
        if ($r['ok']) foreach ($r['items'] as $it) if (preg_match('/^\* SEARCH\s*([\d ]*)/', $it['head'], $m)) foreach (preg_split('/\s+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY) as $i) $ids[] = (int)$i;
        return $ids;
    }
    /** @return array{0:?string,1:?int} raw mail + internal date */
    public function fetch(int $id): array {
        $r = $this->cmd("FETCH $id (INTERNALDATE BODY.PEEK[])"); if (!$r['ok']) return [null, null];
        foreach ($r['items'] as $it) if ($it['lit'] !== null && strpos($it['head'], 'FETCH') !== false) return [$it['lit'], gm_internaldate($it['head'])];
        return [null, null];
    }
    public function logout(): void { try { if ($this->fp) { @fwrite($this->fp, "Z LOGOUT\r\n"); @fclose($this->fp); } } catch (Throwable $e) {} }
}
/** @return array{0:bool,1:string} ok + message (used when the merchant saves credentials) */
function gm_selftest(string $email, string $pass): array {
    $r = gm_bridge_request('/v1/test-login', ['email'=>$email,'appPassword'=>$pass]);
    if (!empty($r['ok'])) return [true, 'Gmail login OK (Render IMAP backend)'];
    if (($r['error'] ?? '') === 'bridge_not_configured') return [false, 'Render Gmail backend is not configured.'];
    if (($r['error'] ?? '') === 'imap_login_failed') return [false, 'Gmail rejected the login. Use a 16-character Gmail App Password.'];
    return [false, 'Could not reach Gmail through the Render backend. Check Render service and IMAP connectivity.'];
}
/** Recent FamPay mails of this merchant. @return array{0:string,1:array,2:string} ok|error, parsed mails, error code */
function gm_recent_mails(array $m): array {
    $payload = gm_bridge_payload($m);
    if ($payload === null) return ['error', [], 'gmail_not_configured'];
    $r = gm_bridge_request('/v1/recent', $payload);
    if (empty($r['ok'])) return ['error', [], ($r['error'] ?? 'imap_connection_failed')];
    return ['ok', $r['emails'] ?? [], ''];
}

/* ------------------------------------------------------------------ verification of one order (automatic) */
/** Same return shape as verify_order(). Matches the order to a FamPay payment mail by exact amount + time. */
function gm_verify_auto(array $o): array {
    $ret = fn($ord, $err = null, $tr = false, $fatal = false) => ['order' => $ord, 'check' => $err ? 'error' : 'ok', 'error' => $err, 'transient' => $tr, 'fatal' => $fatal];
    if (in_array($o['status'], ['success', 'failed', 'refunded'], true)) return ['order' => $o, 'check' => 'cached', 'error' => null, 'transient' => false, 'fatal' => false];
    $cfg = gm_cfg(); $now = time(); $created = strtotime($o['created_at']);
    if ($o['status'] === 'pending' && strtotime($o['expires_at']) < $now) { change_order_status($o, 'expired'); $o = get_order($o['order_id']) ?: $o; }
    if ($o['status'] === 'expired' && $now - $created > $cfg['max_payment_age']) return $ret($o);      // too old to rescue
    if ($o['last_checked'] && ($now - strtotime($o['last_checked'])) < 10) return $ret($o);
    db()->prepare('UPDATE orders SET last_checked = ? WHERE id = ?')->execute([now(), $o['id']]);
    $m = merchant_by_id((int)$o['merchant_id']);
    if (!$m || !gm_ready($m)) return $ret($o, 'The merchant\'s Gmail is not connected.', false, true);
    [$st, $emails, $err] = gm_recent_mails($m);
    if ($err === 'imap_login_failed') gm_set_error((int)$m['id'], 'Gmail login failed. Reconnect with a new App Password.');
    if ($st !== 'ok') return $ret($o, $err === 'imap_login_failed' ? 'The merchant\'s Gmail login failed. The merchant must reconnect Gmail.' : 'Payment check is temporarily unavailable. Retrying…', $err !== 'imap_login_failed', $err === 'imap_login_failed');
    $exp = (int)round((float)$o['amount'] * 100);
    // an older still-open order of the same merchant + amount gets the payment first
    $older = db()->prepare("SELECT COUNT(*) FROM orders WHERE merchant_id = ? AND pay_method = 'gmail' AND status = 'pending' AND amount = ? AND id < ? AND expires_at > ?");
    $older->execute([$o['merchant_id'], $o['amount'], $o['id'], now()]);
    if ((int)$older->fetchColumn() > 0) return $ret($o);
    foreach ($emails as $em) {
        if (!$em['sender_ok'] || $em['amount_paise'] !== $exp || !$em['ref']) continue;
        [$ok] = gm_check_payment_time($cfg, $em, $created, null, $now);
        if (!$ok) continue;
        try {   // each payment mail can confirm only one order
            $c = db()->prepare('SELECT 1 FROM payment_utrs WHERE utr = ?'); $c->execute([$em['ref']]); if ($c->fetchColumn()) continue;
            db()->prepare('INSERT INTO payment_utrs (utr, order_id, merchant_id, amount, received, paid_at, credited_at) VALUES (?,?,?,?,?,?,?)')
                ->execute([$em['ref'], $o['order_id'], $o['merchant_id'], $o['amount'], $exp / 100, date('Y-m-d H:i:s', $em['paid_at']), now()]);
        } catch (Throwable $e) { continue; }
        if (change_order_status($o, 'success')) db()->prepare('UPDATE orders SET utr = ? WHERE id = ?')->execute([$em['ref'], $o['id']]);
        else db()->prepare('DELETE FROM payment_utrs WHERE utr = ?')->execute([$em['ref']]);
        return $ret(get_order($o['order_id']) ?: $o);
    }
    return $ret($o);
}

/* ------------------------------------------------------------------ PayX-style: payer submits the UTR */
const GM_REVIEW_MSG = [
    'amount_mismatch' => 'A payment with this UTR was found, but its amount does not match this order.',
    'amount_unreadable' => 'We found the payment e-mail but could not read the amount.',
    'time_unreadable' => 'We could not confirm the payment time.',
    'payment_before_order' => 'This payment was made before this order was created, so it cannot be used.',
    'payment_too_late' => 'This payment was made too long after the order was created.',
    'future_timestamp' => 'The payment time in the e-mail is invalid.',
    'time_inconsistent' => 'The payment time in the e-mail does not match Gmail\'s arrival time.',
    'payment_after_utr_submit' => 'The payment time is later than the moment the UTR was submitted.',
    'duplicate_utr' => 'This UTR has already been used for another payment.',
    'unverified' => 'This payment could not be verified.',
    'email_not_found_timeout' => 'We could not find this payment. Please check the UTR and submit it again, or contact the merchant.',
];
/** Merchant's Gmail login broke: pause new orders until he reconnects (like PayX "needs attention"). */
function gm_set_error(int $mid, string $msg): void {
    db()->prepare('UPDATE merchants SET gm_ok = 0, gm_err = ? WHERE id = ?')->execute([mb_substr($msg, 0, 160), $mid]);
}
function gm_reject(array $o, string $why): void {
    db()->prepare("UPDATE orders SET reject_reason = ? WHERE id = ? AND status IN ('pending','expired')")->execute([$why, $o['id']]);
}
/** @return array{0:string,1:array,2:string} ok|error, matching mails, error code */
function gm_search_utr(array $m, string $utr): array {
    $payload = gm_bridge_payload($m);
    if ($payload === null) return ['error', [], 'gmail_not_configured'];
    if (!preg_match('/^[A-Z0-9]{8,40}$/', $utr)) return ['error', [], 'bad_utr'];
    $payload['utr'] = $utr;
    $r = gm_bridge_request('/v1/search-utr', $payload);
    if (empty($r['ok'])) return ['error', [], ($r['error'] ?? 'imap_connection_failed')];
    return ['ok', $r['emails'] ?? [], ''];
}
function gm_verify_utr_order(array $o): array {
    $ret = fn($ord, $err = null, $tr = false, $fatal = false) => ['order' => $ord, 'check' => $err ? 'error' : 'ok', 'error' => $err, 'transient' => $tr, 'fatal' => $fatal];
    $cfg = gm_cfg(); $now = time();
    if ($o['status'] === 'pending' && strtotime($o['expires_at']) < $now && empty($o['utr'])) { change_order_status($o, 'expired'); $o = get_order($o['order_id']) ?: $o; }
    if (empty($o['utr']) || !empty($o['reject_reason']) || !in_array($o['status'], ['pending', 'expired'], true)) return $ret($o);
    if ($o['last_checked'] && ($now - strtotime($o['last_checked'])) < 10) return $ret($o);
    db()->prepare('UPDATE orders SET last_checked = ? WHERE id = ?')->execute([now(), $o['id']]);
    $m = merchant_by_id((int)$o['merchant_id']);
    if (!$m || !gm_ready($m)) return $ret($o, 'The merchant\'s payment account is unavailable right now. Please contact the merchant.', false, true);
    [$st, $emails, $err] = gm_search_utr($m, $o['utr']);
    if ($st !== 'ok') {
        if ($err === 'imap_login_failed') { gm_set_error((int)$m['id'], 'Gmail login failed. Reconnect with a new App Password.'); return $ret($o, 'The merchant\'s payment account is unavailable right now. Please contact the merchant.', false, true); }
        return $ret($o, 'Payment check is temporarily unavailable. Retrying…', true);
    }
    $exp = (int)round((float)$o['amount'] * 100); $created = strtotime($o['created_at']); $utrAt = !empty($o['utr_at']) ? strtotime($o['utr_at']) : null;
    $matched = false; $reject = ''; $good = null;
    foreach ($emails as $em) {
        if (!($em['sender_ok'] && $em['utr_match'])) continue;
        $matched = true;
        if ($em['amount_paise'] === null) { $reject = $reject ?: 'amount_unreadable'; continue; }
        if ($em['amount_paise'] !== $exp) { $reject = 'amount_mismatch'; continue; }
        [$ok, $why] = gm_check_payment_time($cfg, $em, $created, $utrAt, $now);
        if (!$ok) { $reject = (!$reject || $reject === 'time_unreadable') ? $why : $reject; continue; }
        $good = $em; break;
    }
    if ($good) {
        try {   // a UTR can pay only ONE order, ever
            foreach (gm_utr_aliases($o['utr']) as $al) { $c = db()->prepare('SELECT 1 FROM payment_utrs WHERE utr = ?'); $c->execute([$al]); if ($c->fetchColumn()) throw new RuntimeException('dup'); }
            db()->prepare('INSERT INTO payment_utrs (utr, order_id, merchant_id, amount, received, paid_at, credited_at) VALUES (?,?,?,?,?,?,?)')
                ->execute([$o['utr'], $o['order_id'], $o['merchant_id'], $o['amount'], $exp / 100, date('Y-m-d H:i:s', $good['paid_at']), now()]);
        } catch (Throwable $e) { gm_reject($o, 'duplicate_utr'); return $ret(get_order($o['order_id']) ?: $o); }
        if (!change_order_status($o, 'success')) db()->prepare('DELETE FROM payment_utrs WHERE utr = ?')->execute([$o['utr']]);
        return $ret(get_order($o['order_id']) ?: $o);
    }
    if ($matched) gm_reject($o, $reject ?: 'unverified');
    elseif ($utrAt && $now - $utrAt > $cfg['verify_max_age']) gm_reject($o, 'email_not_found_timeout');
    return $ret(get_order($o['order_id']) ?: $o);
}
/** Entry point used by verify_order(): UTR flow when a UTR was submitted (or the merchant uses UTR mode), auto-match otherwise. */
function gm_verify_order(array $o): array {
    if (in_array($o['status'], ['success', 'failed', 'refunded'], true)) return ['order' => $o, 'check' => 'cached', 'error' => null, 'transient' => false, 'fatal' => false];
    $m = merchant_by_id((int)$o['merchant_id']);
    if (!empty($o['utr']) || !$m || ($m['gm_verify'] ?? 'utr') !== 'auto') return gm_verify_utr_order($o);
    return gm_verify_auto($o);
}
/** Payer submits a UTR. @return array{0:bool,1:string} */
function gm_submit_utr(array $o, string $raw): array {
    $cfg = gm_cfg(); $utr = gm_normalize_utr($raw);
    if (!$utr) return [false, 'Enter the UTR / transaction ID shown in your UPI app (usually 12 digits).'];
    if (($o['pay_method'] ?? '') !== 'gmail' || !in_array($o['status'], ['pending', 'expired'], true)) return [false, 'This payment can no longer accept a UTR.'];
    if (time() - strtotime($o['created_at']) > $cfg['late_utr_window']) return [false, 'The time to submit a UTR for this order is over.'];
    if ((int)($o['utr_tries'] ?? 0) >= $cfg['max_utr_tries']) return [false, 'Too many attempts for this order. Please contact the merchant.'];
    foreach (gm_utr_aliases($utr) as $al) { $c = db()->prepare('SELECT 1 FROM payment_utrs WHERE utr = ?'); $c->execute([$al]); if ($c->fetchColumn()) return [false, 'This UTR has already been used for another payment.']; }
    $u = db()->prepare("UPDATE orders SET utr = ?, utr_at = ?, reject_reason = NULL, last_checked = NULL, utr_tries = utr_tries + 1 WHERE id = ? AND status IN ('pending','expired')");
    $u->execute([$utr, now(), $o['id']]);
    return $u->rowCount() === 1 ? [true, 'UTR received. Verifying your payment…'] : [false, 'Please try again.'];
}
