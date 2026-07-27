const nativeMapKey = process.env.IOS_MAPS_API_KEY;

export default {
  expo: {
    name: "CodeInspectus FP",
    slug: "codeinspectus-fp",
    ios: {
      config: {
        googleMapsApiKey: nativeMapKey,
      },
    },
    extra: {
      analyticsClientId: process.env.EXPO_PUBLIC_ANALYTICS_CLIENT_ID,
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
