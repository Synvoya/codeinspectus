function helmet(_options: unknown) {}

helmet({ referrerPolicy: { policy: "unsafe-url" } });

const localConfig = {
  key: "Referrer-Policy",
  value: "unsafe-url",
};

settings.set("Permissions-Policy", "camera=*");
res.removeHeader("Referrer-Policy");
res.removeHeader("Permissions-Policy");
void localConfig;
