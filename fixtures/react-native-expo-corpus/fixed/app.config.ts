export default {
  expo: {
    name: "CodeInspectus Fixed",
    slug: "codeinspectus-fixed",
    extra: {
      analyticsClientId: "public-mobile-client",
    },
    updates: {
      enabled: true,
      url: "https://updates.acmeapp.com",
      codeSigningCertificate: "./certs/update.pem",
      codeSigningMetadata: {
        alg: "rsa-v1_5-sha256",
        keyid: "main",
      },
    },
  },
};
