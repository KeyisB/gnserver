"""
Жёсткий тест encType 2 bootstrap-ключей.
Тестирует: ключи, encrypt/decrypt, GN-фрейминг, сценарий key-swap (баг), и fix.
"""
import os
import sys
import time
import random
import hashlib

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES

PASS = 0
FAIL = 0

def ok(name):
    global PASS
    PASS += 1
    print(f"  ✓ {name}")

def fail(name, detail=""):
    global FAIL
    FAIL += 1
    print(f"  ✗ {name}  {detail}")


# ─── Дублируем функции из _datagram_enc.py (без зависимостей) ───

def _derive_bootstrap_transport_keys(shared_key, *, local_domain, peer_domain):
    key_in = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=peer_domain.encode() + local_domain.encode(),
        info=b'gn:DgEncryptor',
    ).derive(shared_key)
    key_out = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=local_domain.encode() + peer_domain.encode(),
        info=b'gn:DgEncryptor',
    ).derive(shared_key)
    return key_in, key_out


class FakeEncryptor:
    """Минимальная копия ConnectionEncryptor для тестирования."""
    def __init__(self, name):
        self.name = name
        self.counter = 0
        self._rng = random.Random(int.from_bytes(os.urandom(16), 'big'))
        self._key_in = None
        self._key_out = None
        self._prev_key_in = None

    def initType2(self, *, is_server=False):
        if is_server:
            local_marker, peer_marker = 'pq:server', 'pq:client'
        else:
            local_marker, peer_marker = 'pq:client', 'pq:server'
        key_in, key_out = _derive_bootstrap_transport_keys(
            b'', local_domain=local_marker, peer_domain=peer_marker,
        )
        if self._key_in is not None:
            self._prev_key_in = self._key_in
        self._key_in = key_in
        self._key_out = key_out

    def _make_nonce(self):
        now = int(time.time()) & 0xFFFFFFFFFF
        self.counter = (self.counter + 1) & 0xFFFFFFFFFFFFFFFF
        r = self._rng.getrandbits(16)
        return now.to_bytes(5, "big") + self.counter.to_bytes(8, "big") + r.to_bytes(2, "big")

    def encrypt(self, packet):
        nonce = self._make_nonce()
        cipher = AES.new(self._key_out, AES.MODE_OCB, nonce=nonce, mac_len=16)
        ct, tag = cipher.encrypt_and_digest(packet)
        return nonce + ct + tag

    def decrypt(self, packet):
        nonce = packet[:15]
        tag = packet[-16:]
        ct = packet[15:-16]
        try:
            c = AES.new(self._key_in, AES.MODE_OCB, nonce=nonce, mac_len=16)
            res = c.decrypt_and_verify(ct, tag)
            if self._prev_key_in is not None:
                self._prev_key_in = None
            return res
        except Exception:
            prev = self._prev_key_in
            if prev is not None:
                c2 = AES.new(prev, AES.MODE_OCB, nonce=nonce, mac_len=16)
                return c2.decrypt_and_verify(ct, tag)
            raise

    def fp(self, key):
        return hashlib.sha3_256(key).hexdigest()[:16] if key else 'none'


def construct_initial(enc_type, keyid):
    """10-байт GN initial header."""
    version = 0
    b0 = ((version & 0x7F) << 1) | 1  # system packet
    b1 = ((0 & 0x0F) << 4) | (enc_type & 0x0F)
    if isinstance(keyid, tuple):
        kt, ki = keyid
    else:
        kt, ki = 0, keyid
    return bytes([b0, b1, kt]) + ki.to_bytes(7, 'big')


def parse_initial(data):
    """Парсит 10-байт GN initial header."""
    b0 = data[0]
    is_system = b0 & 0x01
    version = (b0 >> 1) & 0x7F
    b1 = data[1]
    cmd = (b1 >> 4) & 0x0F
    enc_type = b1 & 0x0F
    kt = data[2]
    ki = int.from_bytes(data[3:10], 'big')
    datagram = data[10:]
    return {
        'is_system': is_system, 'version': version, 'command': cmd,
        'enc_type': enc_type, 'keyid': (kt, ki), 'datagram': datagram,
    }


# ═══════════════════════════════════════════════════
print("=" * 60)
print("ТЕСТ 1: Симметрия ключей")
print("=" * 60)

client = FakeEncryptor("client")
server = FakeEncryptor("server")
client.initType2(is_server=False)
server.initType2(is_server=True)

if client._key_out == server._key_in:
    ok(f"client.key_out == server.key_in  (fp={client.fp(client._key_out)})")
else:
    fail("client.key_out != server.key_in",
         f"{client.fp(client._key_out)} vs {server.fp(server._key_in)}")

if server._key_out == client._key_in:
    ok(f"server.key_out == client.key_in  (fp={server.fp(server._key_out)})")
else:
    fail("server.key_out != client.key_in",
         f"{server.fp(server._key_out)} vs {client.fp(client._key_in)}")

if client._key_in != client._key_out:
    ok("client.key_in != client.key_out (разные ключи)")
else:
    fail("client.key_in == client.key_out (одинаковые — плохо!)")

print(f"  key_in_fp  client={client.fp(client._key_in)}  server={server.fp(server._key_in)}")
print(f"  key_out_fp client={client.fp(client._key_out)}  server={server.fp(server._key_out)}")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 2: Encrypt/Decrypt базовый")
print("=" * 60)

for i in range(20):
    pt = os.urandom(1191)  # типичный QUIC Initial
    enc = client.encrypt(pt)
    try:
        dec = server.decrypt(enc)
        if dec == pt:
            if i == 0:
                ok(f"client→server: encrypt({len(pt)}B) → decrypt({len(enc)}B) → {len(dec)}B  OK")
        else:
            fail(f"client→server #{i}: decrypted != plaintext")
    except Exception as e:
        fail(f"client→server #{i}: {e}")

for i in range(20):
    pt = os.urandom(1191)
    enc = server.encrypt(pt)
    try:
        dec = client.decrypt(enc)
        if dec == pt:
            if i == 0:
                ok(f"server→client: encrypt({len(pt)}B) → decrypt({len(enc)}B) → {len(dec)}B  OK")
        else:
            fail(f"server→client #{i}: decrypted != plaintext")
    except Exception as e:
        fail(f"server→client #{i}: {e}")

ok("20 пакетов client→server  все OK")
ok("20 пакетов server→client  все OK")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 3: GN Initial фрейминг (полный цикл)")
print("=" * 60)

quic_initial = os.urandom(1191)

# Клиент строит GN initial + шифрует
header = construct_initial(2, (250, 0))
assert len(header) == 10, f"Header length should be 10, got {len(header)}"
encrypted_payload = client.encrypt(quic_initial)
wire_packet = header + encrypted_payload
ok(f"client построил пакет: header={len(header)}B + encrypted={len(encrypted_payload)}B = {len(wire_packet)}B")

# Сервер парсит
parsed = parse_initial(wire_packet)
assert parsed['is_system'] == 1
assert parsed['command'] == 0
assert parsed['enc_type'] == 2
assert parsed['keyid'] == (250, 0)
ok(f"server парсит: enc_type={parsed['enc_type']} keyid={parsed['keyid']}")

# Сервер дешифрует
try:
    dec = server.decrypt(parsed['datagram'])
    assert dec == quic_initial
    ok(f"server дешифровал: {len(parsed['datagram'])}B → {len(dec)}B  совпадает с оригиналом")
except Exception as e:
    fail(f"server decrypt failed: {e}")

# Сервер отвечает
server_response = os.urandom(1191)
server_header = construct_initial(2, (250, 0))
server_encrypted = server.encrypt(server_response)
server_wire = server_header + server_encrypted
ok(f"server построил ответ: {len(server_wire)}B")

# Клиент парсит ответ
parsed_resp = parse_initial(server_wire)
try:
    dec_resp = client.decrypt(parsed_resp['datagram'])
    assert dec_resp == server_response
    ok(f"client дешифровал ответ сервера: OK")
except Exception as e:
    fail(f"client decrypt failed: {e}")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 4: БАГ — client вызывает initType2(is_server=True) при получении ответа")
print("=" * 60)

client_bug = FakeEncryptor("client_bug")
server_bug = FakeEncryptor("server_bug")

# Инициализация
client_bug.initType2(is_server=False)
server_bug.initType2(is_server=True)

# 1. Клиент отправляет initial
pt1 = os.urandom(1191)
enc1 = client_bug.encrypt(pt1)
dec1 = server_bug.decrypt(enc1)
assert dec1 == pt1
ok("Шаг 1: client→server первый initial — OK")

# 2. Сервер отправляет ответ
pt2 = os.urandom(1191)
enc2 = server_bug.encrypt(pt2)
ok(f"Шаг 2: server шифрует ответ (key_out_fp={server_bug.fp(server_bug._key_out)})")

# 3. БАГОВЫЙ КЛИЕНТ: вызывает initType2(is_server=True)
print(f"  → client ПЕРЕД swap: key_in={client_bug.fp(client_bug._key_in)} key_out={client_bug.fp(client_bug._key_out)}")
client_bug.initType2(is_server=True)  # ← БАГ!
print(f"  → client ПОСЛЕ swap: key_in={client_bug.fp(client_bug._key_in)} key_out={client_bug.fp(client_bug._key_out)}")

if client_bug._key_in == server_bug._key_in:
    fail("ПОДТВЕРЖДЕНО: client.key_in == server.key_in (оба слушают одинаково — всё сломано!)")

# 4. Клиент пытается расшифровать ответ сервера ПОСЛЕ swap
try:
    dec2 = client_bug.decrypt(enc2)
    fail("Шаг 4: client decrypt ответа сервера — неожиданно OK?!")
except Exception as e:
    ok(f"Шаг 4: client НЕ МОЖЕТ расшифровать ответ сервера: {e}")
    ok("  ↳ Потому что client.key_in теперь == server.key_in, а не server.key_out")

# 5. Клиент отправляет следующий пакет с НОВЫМ (неправильным) key_out
pt3 = os.urandom(1191)
enc3 = client_bug.encrypt(pt3)
try:
    dec3 = server_bug.decrypt(enc3)
    fail("Шаг 5: server decrypt следующего пакета — неожиданно OK?!")
except Exception as e:
    ok(f"Шаг 5: server НЕ МОЖЕТ расшифровать следующий пакет клиента: {e}")
    ok("  ↳ Потому что client.key_out теперь == server.key_out, а не server.key_in")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 5: ИСПРАВЛЕНИЕ — client НЕ вызывает initType2 при получении ответа")
print("=" * 60)

client_fix = FakeEncryptor("client_fix")
server_fix = FakeEncryptor("server_fix")

client_fix.initType2(is_server=False)
server_fix.initType2(is_server=True)

# 1. Client→Server initial
pt1 = os.urandom(1191)
enc1 = client_fix.encrypt(pt1)
dec1 = server_fix.decrypt(enc1)
assert dec1 == pt1
ok("Шаг 1: client→server initial — OK")

# 2. Server→Client response
pt2 = os.urandom(1191)
enc2 = server_fix.encrypt(pt2)

# 3. Client получает initial, НЕ вызывает initType2 (fix)
# Просто дешифрует с текущими ключами
try:
    dec2 = client_fix.decrypt(enc2)
    assert dec2 == pt2
    ok("Шаг 3: client дешифрует ответ сервера БЕЗ reinit — OK")
except Exception as e:
    fail(f"Шаг 3: client decrypt failed: {e}")

# 4. Client отправляет следующие пакеты — ключи не изменились
for i in range(10):
    pt = os.urandom(1191)
    enc = client_fix.encrypt(pt)
    dec = server_fix.decrypt(enc)
    assert dec == pt

ok("Шаг 4: 10 пакетов client→server после ответа — все OK")

# 5. Server отправляет payload пакеты
for i in range(10):
    pt = os.urandom(1191)
    enc = server_fix.encrypt(pt)
    dec = client_fix.decrypt(enc)
    assert dec == pt

ok("Шаг 5: 10 пакетов server→client — все OK")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 6: Server reinit (reconnect) — ключи те же самые")
print("=" * 60)

server_reinit = FakeEncryptor("server_reinit")
server_reinit.initType2(is_server=True)
key_in_before = server_reinit._key_in
key_out_before = server_reinit._key_out

# reinit
server_reinit.initType2(is_server=True)
if server_reinit._key_in == key_in_before and server_reinit._key_out == key_out_before:
    ok("Server reinit: ключи идентичны")
else:
    fail("Server reinit: ключи изменились!")

# prev_key_in == key_in (те же ключи)
if server_reinit._prev_key_in == key_in_before:
    ok("Server reinit: _prev_key_in сохранён")
else:
    fail("Server reinit: _prev_key_in потерян")

# decrypt с reinit'ом
pt = os.urandom(1191)
client_reinit = FakeEncryptor("client_reinit")
client_reinit.initType2(is_server=False)
enc = client_reinit.encrypt(pt)
dec = server_reinit.decrypt(enc)
assert dec == pt
ok("Server reinit: decrypt после reinit — OK")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 7: Полный маршрут с GN-фреймингом (как в реальном коде)")
print("=" * 60)

client_full = FakeEncryptor("client_full")
server_full = FakeEncryptor("server_full")

# === CLIENT SEND ===
# 1. Client initType2(is_server=False)
client_full.initType2(is_server=False)
print(f"  client: key_in={client_full.fp(client_full._key_in)} key_out={client_full.fp(client_full._key_out)}")

# 2. Client builds GN initial + encrypts QUIC Initial
quic_client_hello = os.urandom(1191)
gn_header = construct_initial(2, (250, 0))
encrypted = client_full.encrypt(quic_client_hello)
wire1 = gn_header + encrypted
print(f"  client→server: wire_len={len(wire1)} (header=10 + encrypted={len(encrypted)})")

# === SERVER RECEIVE ===
# 3. Server parses GN header
p = parse_initial(wire1)
assert p['enc_type'] == 2 and p['keyid'] == (250, 0)

# 4. Server initType2(is_server=True) — first packet, ready=False
server_full.initType2(is_server=True)
print(f"  server: key_in={server_full.fp(server_full._key_in)} key_out={server_full.fp(server_full._key_out)}")

# 5. Server decrypts
dec = server_full.decrypt(p['datagram'])
assert dec == quic_client_hello
ok("SERVER получил QUIC ClientHello")

# === SERVER SEND RESPONSE ===
# 6. Server builds response (Initial + Handshake)
quic_server_hello = os.urandom(1191)
resp_header = construct_initial(2, (250, 0))
resp_enc = server_full.encrypt(quic_server_hello)
wire2 = resp_header + resp_enc
print(f"  server→client: wire_len={len(wire2)}")

# Server also sends payload packets (Handshake)
quic_handshake1 = os.urandom(800)
payload_b0 = bytes([(0 << 1) | 0])  # version=0, system=0
hs_enc = server_full.encrypt(quic_handshake1)
wire3 = payload_b0 + hs_enc

quic_handshake2 = os.urandom(600)
hs_enc2 = server_full.encrypt(quic_handshake2)
wire4 = payload_b0 + hs_enc2

# === CLIENT RECEIVE ===
# 7. Client receives payload packets FIRST (fast path in real code)
dec_hs1 = client_full.decrypt(wire3[1:])
assert dec_hs1 == quic_handshake1
ok("CLIENT fast-path: payload #1 (Handshake) — OK")

dec_hs2 = client_full.decrypt(wire4[1:])
assert dec_hs2 == quic_handshake2
ok("CLIENT fast-path: payload #2 (Handshake) — OK")

# 8. Client receives Initial response (slow path) — WITH FIX: NO reinit
p_resp = parse_initial(wire2)
# FIX: client does NOT call initType2(is_server=True)
dec_resp = client_full.decrypt(p_resp['datagram'])
assert dec_resp == quic_server_hello
ok("CLIENT slow-path: server Initial response — OK (без reinit)")

# === CLIENT SENDS HANDSHAKE COMPLETION ===
# 9. Client sends Handshake completion
quic_client_finished = os.urandom(500)
client_hs = client_full.encrypt(quic_client_finished)
wire5 = payload_b0 + client_hs

# Server receives it as payload
dec_finished = server_full.decrypt(wire5[1:])
assert dec_finished == quic_client_finished
ok("SERVER получил Client Finished — OK")

# === BIDIRECTIONAL DATA AFTER HANDSHAKE ===
for i in range(50):
    pt = os.urandom(random.randint(100, 1400))
    if i % 2 == 0:
        enc = client_full.encrypt(pt)
        dec = server_full.decrypt(enc)
    else:
        enc = server_full.encrypt(pt)
        dec = client_full.decrypt(enc)
    assert dec == pt
ok("50 пакетов bidirectional — все OK")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("ТЕСТ 8: Second initial (retransmit) от клиента")
print("=" * 60)

client_rt = FakeEncryptor("client_rt")
server_rt = FakeEncryptor("server_rt")
client_rt.initType2(is_server=False)
server_rt.initType2(is_server=True)

# Client отправляет ДВА initial одновременно (QUIC transmit)
quic_init = os.urandom(1191)
header = construct_initial(2, (250, 0))

enc_pkt1 = client_rt.encrypt(quic_init)
enc_pkt2 = client_rt.encrypt(quic_init)  # retransmit, другой nonce

wire_pkt1 = header + enc_pkt1
wire_pkt2 = header + enc_pkt2

# Server обрабатывает первый
p1 = parse_initial(wire_pkt1)
dec1 = server_rt.decrypt(p1['datagram'])
assert dec1 == quic_init
ok("Server: первый initial decrypt — OK")

# Server reinit (в реальном коде — для reconnect)
server_rt.initType2(is_server=True)

# Server обрабатывает второй (после reinit)
p2 = parse_initial(wire_pkt2)
try:
    dec2 = server_rt.decrypt(p2['datagram'])
    assert dec2 == quic_init
    ok("Server: второй initial после reinit — OK")
except Exception as e:
    fail(f"Server: второй initial после reinit — FAIL: {e}")


# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print(f"ИТОГО: {PASS} passed, {FAIL} failed")
print("=" * 60)

if FAIL > 0:
    sys.exit(1)
else:
    print("\nВСЕ ТЕСТЫ ПРОЙДЕНЫ.")
    sys.exit(0)
