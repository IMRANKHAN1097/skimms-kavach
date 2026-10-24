# SKIMMS Kavach - Smart Kavach for Intelligent Mine Monitoring
Team HEXACREW, University of Calcutta, SIH26039. Prototype early-warning system, NOT a certified gas detector.

    cd server && npm install && npm test      # 9 automated checks
    ADMIN_PASS=your-strong-pass SECRET=long-random npm start      # http://localhost:3000

- Control Room: supervisor login -> + Register helmet (ESP32 ID, tag, name, 4-digit PIN, area) -> Create Key & Save (device key shown once).
- Worker View: ESP32 ID + PIN. Helmet firmware POSTs to /api/telemetry with header x-device-key (firmware/wifi_uplink.ino).
- Deploy free: push to GitHub, Render web service (render.yaml, rootDir server). Set ADMIN_PASS. Free hosts wipe files on restart: use Backup workers -> WORKERS_JSON.
- Optional alerts: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, or WEBHOOK_URL. ESCALATE_S sets the auto-escalation delay (default 120).
- Never commit .env, server/data/, keystores or google-services.json. There is no demo bypass and no built-in default password in production.
