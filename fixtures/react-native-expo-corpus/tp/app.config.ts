const billingSecret = process.env.BILLING_API_SECRET;

export default {
  expo: {
    name: "CodeInspectus TP",
    slug: "codeinspectus-tp",
    extra: {
      billingSecret,
    },
    updates: {
      enabled: true,
      url: "http://updates.acmeapp.com",
    },
  },
};
