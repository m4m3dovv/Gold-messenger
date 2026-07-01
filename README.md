# Gold Mesaj — şifrəli Telegram Mini App messenger (minimal skeleton)

Telefon nömrəsi və e-poçt tələb etmədən, **ucdan-uca şifrəli (E2E)**
mətn/şəkil/video/səs mesajlaşma. Hər istifadəçi qeydiyyatda yalnız bir **ad**
yazır və ona avtomatik bir **rəqəm ID** (`#000042`) verilir.

## Arxitektura

```
┌─────────────────────────────────────────────────────────────┐
│  Telegram client (mobil/desktop)                              │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  Mini App (WebView)                                    │   │
│  │  - webapp/app.js  (UI, qeydiyyat, chat, media)         │   │
│  │  - crypto-engine  (X25519 + 10-qat şifrələmə, BURADA   │   │
│  │    işləyir — server heç vaxt açıq mətn görmür)         │   │
│  │  - private key -> Telegram CloudStorage (cihazda)      │   │
│  └───────────────────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────────────────┘
                         │ HTTPS (REST + WebSocket)
┌───────────────────────▼─────────────────────────────────────┐
│  Railway: Node.js servisi (server/)                           │
│  - Express API  (/api/*)                                       │
│  - WebSocket    (/ws)  — real-time mesaj push                 │
│  - grammY bot   (polling) — /start + Menu Button               │
│  - PostgreSQL   — users (ad, ID, public key) + messages        │
│                    (şifrəli paket, server üçün opaque bayt)    │
└─────────────────────────────────────────────────────────────┘
```

**Açar prinsip:** server yalnız `users.public_key` və `messages.packet`
(BYTEA, tam şifrələnmiş) saxlayır. `private key` heç vaxt serverə getmir —
yalnız Telegram CloudStorage-da (istifadəçinin öz hesabına bağlı) qalır.

## Quraşdırma

```bash
cp .env.example .env
# .env-i doldur: BOT_TOKEN (@BotFather-dan), DATABASE_URL (Railway Postgres)

npm install        # postinstall avtomatik webapp/dist/bundle.js yaradır
npm test           # crypto-engine (17) + telegramAuth (9) + smoke test
```

## Railway-də deploy

1. Bu qovluğu GitHub repo-ya at (və ya Railway CLI ilə birbaşa deploy et).
2. Railway-də **New Project → Deploy from GitHub repo**.
3. **+ New → Database → PostgreSQL** əlavə et — `DATABASE_URL` avtomatik
   servisin env-inə bağlanır.
4. Servisin **Variables** bölməsində əlavə et:
   - `BOT_TOKEN` — @BotFather-dan aldığın token
   - `MINIAPP_URL` — Railway-in verdiyi domen, məs.
     `https://gold-messenger.up.railway.app` (Settings → Networking →
     Generate Domain)
5. Deploy. Build mərhələsində `npm install` (→ `postinstall` ilə bundle
   avtomatik yaranır), `npm start` ilə server başlayır.
6. Bot artıq polling ilə işləyir (webhook lazım deyil). `/start` yaz və ya
   bot-un menu düyməsinə (✏️-nin yanında) bas — Mini App açılacaq.

## Lokal test (real Telegram olmadan)

WebSocket və CloudStorage real Telegram mühiti tələb edir, amma **bütün
backend API**-ni curl ilə test edə bilərsən:

```bash
npm start &                                  # server :3000-də
node scripts/gen-test-initdata.mjs \
  --id=100000001 --name=Sen --username=sen   # imzalanmış initData + curl nümunələri çıxarır
```

Çıxan curl əmrlərini işlədərək `/api/register`, `/api/me`,
`/api/conversations` cavablarını yoxla — bu, Postgres bağlantısının və
Telegram auth-un düzgün işlədiyini real bot/Mini App açmadan göstərir.

## API reference

Bütün sorğular `initData` daşıyır (GET-də `?initData=`, POST-da body-də) —
bax `server/telegramAuth.js`.

| Method | Path | Açıqlama |
|---|---|---|
| GET | `/health` | sağlamlıq yoxlaması |
| POST | `/api/register` | `{username, publicKey}` → profil yaradır (1 Telegram hesabı = 1 profil, idempotent) |
| GET | `/api/me` | öz profilini qaytarır (`registered:false` əgər yoxdursa) |
| GET | `/api/users/:username` | başqasının `{id, username, publicKey}`-i (yeni söhbət üçün) |
| GET | `/api/conversations` | söhbət siyahısı (metadata — paket yox) |
| POST | `/api/messages` | `{recipientId, mediaType, packet(base64)}` → göndərir + WS push |
| GET | `/api/messages/:peerId?afterId=0` | söhbət tarixçəsi (hər iki istiqamət) |
| WS | `/ws?initData=...` | real-time `{type:'message', ...}` push |

## Şifrələmə

Bax **`crypto-engine/README.md`** — X25519 ECDH → HKDF (10 müstəqil açar) →
10 qat (ChaCha20, AES-256-GCM, AES-256-CBC, XSalsa20, Camellia-tipli Feistel,
TripleXOR, BitTransp, Feistel+BLAKE3, BLAKE3-MAC, HMAC-SHA256). Mətn, şəkil,
video, səs — hamısı eyni `encryptMessage(bytes, shared, salt)` funksiyasından
keçir.

## Verilənlər bazası

Schema server başlayanda avtomatik yaranır (`initSchema()`,
`server/db.js`):

- **users**: `id, telegram_id (gizli), username (unique), public_key, created_at`
- **messages**: `id, sender_id, recipient_id, media_type, packet (BYTEA), created_at`

## Məhdudiyyətlər / növbəti addımlar

- **Media ölçüsü**: hazırda JSON+base64 ilə ötürülür, server limiti 20MB →
  praktiki fayl limiti ~14MB (`webapp/app.js`-də `MAX`). Daha böyük video
  üçün: multipart/streaming upload + obyekt storage (S3/R2/Backblaze),
  Postgres BYTEA əvəzinə.
- **Açar itkisi**: istifadəçi Telegram CloudStorage-ı təmizləsə/başqa
  cihazda fərqli açar yaransa, köhnə söhbətlər deşifr olunmaz (ECDH
  uyğunsuzluğu). Tövsiyə: `/api/update-key` endpoint-i + "açarı yenilə"
  axını (digər tərəfə "açar dəyişdi" bildirişi ilə birgə).
- **Böyük media performansı**: L5/L8 qatları ~3MB/s işləyir — çoxlu MB-lıq
  video üçün Mini App-da Web Worker-ə köçürmək tövsiyə olunur (UI
  bloklanmasın).
- **Qrup söhbətləri** yoxdur (yalnız 1-1).
- "Oxundu" bildirişi, mesaj silmə/redaktə, push notification (Mini App
  bağlı olanda) hələ yoxdur.
- **Username validasiyası** minimaldır (yalnız uzunluq). Lazım olsa simvol
  məhdudiyyəti/lowercase-unikallıq əlavə et.
- **Rate limiting** yoxdur — produksiyaya keçməzdən əvvəl əlavə et (məs.
  `express-rate-limit`).

## Fayl strukturu

```
gold-messenger/
├── package.json
├── .env.example
├── build.mjs                  # esbuild → webapp/dist/bundle.js
├── crypto-engine/              # 10-qat şifrələmə (bax öz README-si)
├── server/
│   ├── index.js                 # Express + WebSocket + statik fayllar
│   ├── db.js                    # PostgreSQL (schema + sorğular)
│   ├── telegramAuth.js          # initData doğrulanması
│   └── bot.js                   # grammY bot (/start, menu button)
├── webapp/
│   ├── index.html               # 3 ekran: qeydiyyat / chat list / chat
│   ├── style.css                # gold/black "Gold Mesaj" dizaynı
│   ├── app.js                   # Mini App məntiqi
│   └── dist/bundle.js           # (build artefaktı, npm install ilə yaranır)
├── test/
│   ├── crypto.test.mjs          # 10-qat pipeline (17 test)
│   ├── telegramAuth.test.mjs    # initData validasiyası (9 test)
│   └── smoke.test.mjs           # tam E2E: qeydiyyat→chat→şifrəli mesaj
└── scripts/
    └── gen-test-initdata.mjs    # lokal curl testi üçün initData generatoru
```
