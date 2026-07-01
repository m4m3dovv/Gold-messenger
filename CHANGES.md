# Yeniliklər — xülasə

Bu patch əvvəlki söhbətdə razılaşdığımız 7 xüsusiyyəti + admin paneli əlavə edir.
Kod repoda (server/, webapp/, admin/) tətbiq olunub, sintaksis yoxlanılıb və
mövcud crypto/auth/smoke testləri keçir.

## 1) Açar bərpası / key rotation
- `server/db.js`: `users.key_version`, `key_updated_at`
- `POST /api/key/rotate` — yeni public key-i qeyd edir, bütün əvvəlki
  həmsöhbətlərə WS + bot bildirişi göndərir (`⚠️ X açarını yenilədi`)
- `webapp/app.js` → `reconcileIdentity()` — hər açılışda lokal açarla server
  açarını müqayisə edir, uyğunsuzluqda avtomatik rotasiya edir (CloudStorage
  silinəndə əlaqə qırılmır, sadəcə xəbərdarlıq göstərilir)

## 2) Rate limiting
- `express-rate-limit`: bütün `/api/` üçün ümumi limit + `/api/register`
  və mesaj göndərmə endpoint-ləri üçün daha sərt limitlər

## 3) Oxundu bildirişi + mesaj silmə/redaktə
- DB: `messages.read_at`, `deleted_at`, `edited_at`
- `POST /api/messages/:id/read`, `POST /api/messages/read-all`
- `DELETE /api/messages/:id` (yalnız göndərən, hər iki tərəf üçün silir)
- `PUT /api/messages/:id` (yenidən şifrələnmiş paket ilə redaktə)
- Klient: bubble üzərində ✏️/🗑️ düymələri, ✓/✓✓ tick-lər, WS ilə real-time yenilənmə

## 4) Push bildirişlər (bot vasitəsilə)
- `server/notify.js` — istifadəçi WebSocket-ə qoşulu deyilsə, bot ona
  "yeni mesajın var" bildirişi göndərir (məzmun YOX, yalnız bildiriş)

## 5) Böyük media üçün obyekt deposu (S3-uyğun)
- `server/media.js` — opsional. `.env`-də S3 dəyişənləri boşdursa, əvvəlki
  Postgres BYTEA davranışı davam edir. Doldursan, `S3_INLINE_MAX_BYTES`-dan
  böyük paketlər avtomatik obyekt deposuna gedir, DB-də yalnız pointer qalır.

## 6) Qrup söhbətləri
- Yeni cədvəllər: `groups`, `group_members`, `group_messages`,
  `group_message_packets`
- Şifrələmə server-side dəyişmir: klient hər üzv üçün mesajı ayrıca
  şifrələyir (mövcud X25519 pairwise pipeline ilə), server yalnız paylayır —
  server heç vaxt qrup açarı və ya plaintext görmür
- `POST/GET /api/groups`, `/api/groups/:id/members`, `/api/groups/:id/messages`
- Klient: "Qruplar" tab-ı, qrup yaratma, qrup söhbət ekranı

## 7) Username validasiyası
- `server/username.js` — 3-24 simvol, unicode hərflə başlamalı, reserved
  sözlər (admin, root, support və s.) qadağan, case-insensitive unikallıq

## + Admin panel
- `/admin` — ayrıca statik panel (login, statistika, istifadəçi siyahısı,
  axtarış, blokla/blokdan çıxar)
- `server/adminAuth.js` — JWT-based, tək admin hesabı (`.env`-də
  `ADMIN_USERNAME` + `ADMIN_PASSWORD_HASH`)
- **Vacib:** admin heç vaxt mesaj məzmununu görmür — yalnız metadata
  (username, son aktivlik, ban statusu). Bu, E2E şifrələmə modelini pozmur.

---

## Deploy etməzdən əvvəl et
1. `npm install` (yeni paketlər: express-rate-limit, jsonwebtoken, bcryptjs, @aws-sdk/client-s3)
2. `.env.example`-ə bax, ən azı bunları doldur:
   - `ADMIN_USERNAME` + `node scripts/hash-admin-password.mjs "parolun"` çıxışından `ADMIN_PASSWORD_HASH`
   - `ADMIN_JWT_SECRET` (təsadüfi uzun sətir)
3. S3 dəyişənlərini boş burax, sonra istəsən qoşarsan (Cloudflare R2 pulsuz tier tövsiyə edirəm)
4. DB sxemi `initSchema()` ilə avtomatik migrasiya olunur (`ALTER TABLE ... IF NOT EXISTS`),
   mövcud verilənlər itmir
5. `npm test` işə sal, sonra `npm run dev` ilə lokal yoxla

## Bilinməli məhdudiyyətlər (dürüst olmaq üçün)
- Qrup söhbətlərində üzv əlavə etmək API-si var, amma UI-da yalnız qrup
  yaratma zamanı ID siyahısı daxil edilir — sonradan üzv əlavə etmək üçün
  hələlik yalnız API mövcuddur (UI-a əlavə etmək asandır, sadəcə vaxt məsələsi)
- Açar rotasiyası "kor etibar" modelindədir — Signal-dakı kimi tam
  "safety number" yoxlaması yoxdur, sadəcə xəbərdarlıq göstərilir
- Media obyekt deposu real S3/R2 credential-ları ilə test edilməyib (bu
  mühitdə şəbəkə girişi yoxdur) — kod məntiqi düzgündür, amma production-a
  keçməzdən əvvəl öz bucket-ində sınaqdan keçir
- Admin login "tək admin hesabı" modelindədir, çox-adminli sistem deyil
