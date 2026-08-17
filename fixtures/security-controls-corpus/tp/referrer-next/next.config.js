module.exports = {
  async headers() {
    return [{
      source: "/:path*",
      headers: [{
        key: "Referrer-Policy",
        value: "origin, made-up-future-token, unsafe-url",
      }],
    }];
  },
};
