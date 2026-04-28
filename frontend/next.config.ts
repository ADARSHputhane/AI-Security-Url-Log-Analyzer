import type { NextConfig } from "next";

const extraOrigins = process.env.NEXT_DEV_ORIGINS
  ? process.env.NEXT_DEV_ORIGINS.split(",").map((o) => o.trim())
  : [];

const nextConfig: NextConfig = {
  allowedDevOrigins: extraOrigins,
};

export default nextConfig;
