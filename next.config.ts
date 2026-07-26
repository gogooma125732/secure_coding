import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    // Vinext classifies multipart POST requests as progressive server-action
    // candidates before dispatching route handlers. Its default 1 MB action
    // limit would therefore reject valid product images before /api/products
    // can enforce the application's 5 MB image policy.
    serverActions: {
      bodySizeLimit: "6mb",
    },
  },
};

export default nextConfig;
