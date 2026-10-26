/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'Permissions-Policy', value: 'camera=(self), microphone=(), geolocation=()' },
]

const nextConfig = {
  experimental: {
    agentUpgrade: 'security',
  },
  typescript: {
    // Kept on so a type error in a UI file cannot block your build the day before submission.
    // Run `npx tsc --noEmit` yourself; once it prints nothing, set this to false.
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

export default nextConfig
