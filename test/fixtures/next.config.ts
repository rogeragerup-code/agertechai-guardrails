// Deliberately-insecure fixture — proves next.config.* at the repo root is
// scanned and the headers() key/value CORS form (value on the next line) fires.
const nextConfig = {
  async headers() {
    return [
      {
        source: "/api/:path*",
        headers: [
          {
            key: "Access-Control-Allow-Origin",
            value: "*",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
