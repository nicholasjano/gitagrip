import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  transpilePackages: ['@gitagrip/shared'],
  output: 'standalone',
};

export default nextConfig;
