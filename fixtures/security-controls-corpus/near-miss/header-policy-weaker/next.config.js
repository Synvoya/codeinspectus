module.exports = {
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "Referrer-Policy", value: "origin-when-cross-origin" },
        { key: "Permissions-Policy", value: "camera=(self \"https://video.example\")" },
      ],
    }];
  },
};
