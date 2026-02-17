<?php
// plc_q_toggle.php
// Single-file PHP page to set PLC IP and toggle Q0-Q7 via FC4A-style ENQ framing over TCP:2101.

declare(strict_types=1);
session_start();

const PLC_PORT = 2101;

function bcc_xor(string $data): string {
    $b = 0;
    $len = strlen($data);
    for ($i = 0; $i < $len; $i++) {
        $b ^= ord($data[$i]);
    }
    return strtoupper(str_pad(dechex($b), 2, '0', STR_PAD_LEFT)); // 2 ASCII hex chars
}

function frame(string $msg): string {
    return $msg . bcc_xor($msg) . "\r";
}

function recv_until_cr($fp, int $limit = 4096): string {
    $buf = '';
    while (strlen($buf) < $limit) {
        $chunk = fread($fp, 256);
        if ($chunk === '' || $chunk === false) break;
        $buf .= $chunk;
        if (strpos($chunk, "\r") !== false) break;
    }
    return $buf;
}

function xmit(string $ip, string $payload, float $timeout_sec = 2.0): string {
    $errno = 0;
    $errstr = '';
    $fp = @fsockopen($ip, PLC_PORT, $errno, $errstr, $timeout_sec);
    if (!$fp) {
        throw new RuntimeException("Connect failed: $errstr ($errno)");
    }
    stream_set_timeout($fp, (int)$timeout_sec, (int)(($timeout_sec - (int)$timeout_sec) * 1_000_000));

    $written = fwrite($fp, $payload);
    if ($written === false || $written !== strlen($payload)) {
        fclose($fp);
        throw new RuntimeException("Send failed");
    }

    $rx = recv_until_cr($fp);
    fclose($fp);
    return $rx;
}

function write_y_bit(string $ip, int $bit_index, int $value, string $device = "FF"): string {
    if ($bit_index < 0 || $bit_index > 7) throw new InvalidArgumentException("bit_index must be 0..7");
    if ($value !== 0 && $value !== 1) throw new InvalidArgumentException("value must be 0 or 1");
    if (!preg_match('/^[0-9A-Fa-f]{2}$/', $device)) throw new InvalidArgumentException("device must be 2 hex chars");

    $addr = str_pad((string)$bit_index, 4, '0', STR_PAD_LEFT); // 0000..0007
    $msg  = "\x05" . strtoupper($device) . "0W" . "y" . $addr . ($value ? "1" : "0");
    return xmit($ip, frame($msg));
}

function write_m_bit(string $ip, int $bit_addr, int $value, string $device = "FF"): string {
    if ($bit_addr < 0 || $bit_addr > 9999) throw new InvalidArgumentException("bit_addr must be 0..9999");
    if ($value !== 0 && $value !== 1) throw new InvalidArgumentException("value must be 0 or 1");
    if (!preg_match('/^[0-9A-Fa-f]{2}$/', $device)) throw new InvalidArgumentException("device must be 2 hex chars");

    $addr = str_pad((string)$bit_addr, 4, '0', STR_PAD_LEFT); // e.g. 8002 -> "8002"
    $msg  = "\x05" . strtoupper($device) . "0W" . "m" . $addr . ($value ? "1" : "0");
    return xmit($ip, frame($msg));
}

function force_pulse_m8002(string $ip, string $device = "FF", int $pulse_ms = 100): array {
    // Send 1 then 0 (momentary)
    $rx1 = write_m_bit($ip, 8002, 1, $device);
    usleep($pulse_ms * 1000);
    $rx0 = write_m_bit($ip, 8002, 0, $device);
    return [$rx1, $rx0];
}


function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

// ------------------- State -------------------
if (!isset($_SESSION['ip'])) $_SESSION['ip'] = '10.1.0.175';
if (!isset($_SESSION['q']))  $_SESSION['q']  = array_fill(0, 8, 0);

$last_rx = null;
$last_tx_hex = null;
$last_err = null;

// ------------------- Actions -------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'set_ip') {
        $ip_in = trim((string)($_POST['ip'] ?? ''));
        if (!filter_var($ip_in, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $last_err = "Invalid IPv4 address.";
        } else {
            $_SESSION['ip'] = $ip_in;
        }
    }
    elseif ($action === 'toggle_q') {
        $q = (int)($_POST['q'] ?? -1);
        if ($q < 0 || $q > 7) {
            $last_err = "Bad Q index.";
        } else {
            $ip = $_SESSION['ip'];
            $new_val = $_SESSION['q'][$q] ? 0 : 1;

            // Build TX for debug display too
            $addr = str_pad((string)$q, 4, '0', STR_PAD_LEFT);
            $msg  = "\x05" . "FF" . "0W" . "y" . $addr . ($new_val ? "1" : "0");
            $tx   = frame($msg);
            $last_tx_hex = strtoupper(bin2hex($tx));

            try {
                $last_rx = write_y_bit($ip, $q, $new_val, "FF");
                $_SESSION['q'][$q] = $new_val;
            } catch (Throwable $e) {
                $last_err = $e->getMessage();
            }
        }
    }
    elseif ($action === 'force_stop') {
        $ip = $_SESSION['ip'];

        // Show the "set 1" TX in the UI (optional)
        $msg = "\x05" . "FF" . "0W" . "m" . "8002" . "1";
        $tx  = frame($msg);
        $last_tx_hex = strtoupper(bin2hex($tx));

        try {
            [$rx1, $rx0] = force_pulse_m8002($ip, "FF", 100);
            $last_rx = "PULSE RX1=" . $rx1 . " | RX0=" . $rx0;
        } catch (Throwable $e) {
            $last_err = $e->getMessage();
        }
    }
}


$ip = $_SESSION['ip'];
$q_state = $_SESSION['q'];

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PLC Q0–Q7 Toggle</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 24px; max-width: 900px; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin-top: 16px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 12px; }
    button { padding: 10px 12px; border-radius: 10px; border: 1px solid #aaa; cursor: pointer; }
    button.on { font-weight: 700; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .err { color: #b00020; }
    .ok  { color: #0b6b0b; }
    input[type="text"] { padding: 8px 10px; border-radius: 10px; border: 1px solid #aaa; width: 180px; }
    .statusline { font-size: 18px; }
  </style>
</head>
<body>
  <h1>PLC Outputs (Q0–Q7)</h1>

  <div class="card">
    <form method="post" class="row">
      <input type="hidden" name="action" value="set_ip" />
      <label>
        PLC IP:
        <input type="text" name="ip" value="<?=h($ip)?>" />
      </label>
      <button type="submit">Set IP</button>
      <span class="mono">Port <?=PLC_PORT?></span>
    </form>
    <?php if ($last_err): ?>
      <div class="err" style="margin-top:10px;"><?=h($last_err)?></div>
    <?php endif; ?>
  </div>

  <div class="card">
    <div class="grid">
      <?php for ($i=0; $i<8; $i++): ?>
        <?php $on = (int)$q_state[$i] === 1; ?>
        <form method="post">
          <input type="hidden" name="action" value="toggle_q" />
          <input type="hidden" name="q" value="<?=$i?>" />
          <button type="submit" class="<?=$on ? 'on' : ''?>">
            <span class="statusline">Q<?=$i?> <?= $on ? 'ON' : 'OFF' ?></span>
          </button>
        </form>
      <?php endfor; ?>
    </div>
  </div>
  
  <div class="card">
      <form method="post">
          <input type="hidden" name="action" value="force_stop" />
          <button type="submit">
            <span class="statusline">Force STOP (M8002)</span>
          </button>
      </form>
  </div>
  
  <div class="card">
    <h3>Last transaction</h3>
    <?php if ($last_tx_hex): ?>
      <div class="mono"><b>TX (hex):</b> <?=h($last_tx_hex)?></div>
    <?php else: ?>
      <div class="mono">No TX yet.</div>
    <?php endif; ?>

    <?php if ($last_rx !== null): ?>
      <div class="mono" style="margin-top:8px;"><b>RX (raw):</b> <?=h($last_rx)?></div>
      <div class="mono"><b>RX (hex):</b> <?=h(strtoupper(bin2hex($last_rx)))?></div>
    <?php endif; ?>
  </div>
</body>
</html>
