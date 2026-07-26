module.exports = {
  async headers() {
    return [
      {
        source: "/admin/:path*",
        headers: [
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains",
          },
        ],
      },
      {
        source: "/legacy/:path*",
        headers: [
          {
            key: "Strict-Transport-Security",
            value: "max-age=0",
          },
        ],
      },
    ];
  },
};
