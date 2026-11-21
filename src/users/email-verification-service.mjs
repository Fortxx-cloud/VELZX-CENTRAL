import { createIpFingerprint } from '../security/ip-fingerprint.mjs';

export function createEmailVerificationService({
  repository,
  env = process.env,
}) {
  if (
    !repository ||
    typeof repository.verifyEmailToken !== 'function'
  ) {
    throw new TypeError('User repository tidak valid');
  }

  return {
    async verifyEmailToken({
      verificationToken,
      ingressVerification,
    }) {
      if (
        !ingressVerification ||
        ingressVerification.accepted !== true ||
        typeof ingressVerification.clientIp !== 'string'
      ) {
        throw new Error('Verifikasi ingress tidak valid');
      }

      const ipFingerprint = createIpFingerprint({
        ip: ingressVerification.clientIp,
        pepper: env.REGISTRATION_IP_PEPPER,
      });

      return repository.verifyEmailToken({
        verificationToken,
        ipFingerprint,
      });
    },
  };
}
