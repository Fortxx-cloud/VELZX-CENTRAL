export function getEmailConfig(env = process.env) {
  const appOrigin = env.APP_ORIGIN?.trim();

  if (!appOrigin) {
    throw new Error('APP_ORIGIN wajib dikonfigurasi');
  }

  let parsedOrigin;

  try {
    parsedOrigin = new URL(appOrigin);
  } catch {
    throw new Error('APP_ORIGIN tidak valid');
  }

  if (!['http:', 'https:'].includes(parsedOrigin.protocol)) {
    throw new Error('APP_ORIGIN harus menggunakan HTTP atau HTTPS');
  }

  const keys = [];

  // Key 1 = primary, key 2-9 = backup.
  // Setiap key wajib memiliki sender address masing-masing.
  // Key 10 sengaja tidak dibaca.
  for (let number = 1; number <= 9; number++) {
    const value = env[`RESEN_API_KEY${number}`]?.trim();

    if (!value) continue;

    const from = env[`RESEN_EMAIL_FROM${number}`]?.trim();

    if (!from) {
      throw new Error(`RESEN_EMAIL_FROM${number} wajib dikonfigurasi untuk key ${number}`);
    }

    keys.push({ number, value, from });
  }

  if (keys.length === 0) {
    throw new Error('Tidak ada Resend API key yang tersedia');
  }

  return { appOrigin: parsedOrigin.origin, keys };
}
