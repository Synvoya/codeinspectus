module.exports = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy-Report-Only",
            value: "default-src *; script-src 'unsafe-eval'",
          },
        ],
      },
    ];
  },
};
