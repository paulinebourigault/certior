/** @type {import('next').NextConfig} */
const isDev = process.env.NODE_ENV !== "production";

const nextConfig = {
  reactStrictMode: true,
  // Keep development and production artifacts isolated so `next dev`
  // does not reuse or corrupt the production build output.
  distDir: isDev ? ".next-dev" : ".next",
  async rewrites() {
    const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    return [
      { source: "/api/:path*", destination: `${apiBase}/api/:path*` },
      { source: "/ws/:path*", destination: `${apiBase}/ws/:path*` },
      { source: "/health", destination: `${apiBase}/health` },
    ];
  },
};

module.exports = nextConfig;
