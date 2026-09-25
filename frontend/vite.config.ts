import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// Application Data
import siteConfiguration from './config/site.json'

// Custom Build Tools
import siteConfig from './build-tools/siteConfig'
import errorOverlay from './build-tools/errorOverlay'
import reactRefreshFallback from './build-tools/reactRefreshFallback'
import componentKit from './build-tools/componentKit'

export default defineConfig(({ mode }) => {
  const emitSourcemaps = mode === 'development'

  return {
    base: process.env.PUBLIC_URL ? `${process.env.PUBLIC_URL}/` : '/',
    build: {
      sourcemap: emitSourcemaps ? 'inline' : false,
      minify: !emitSourcemaps,
    },
    plugins: [
      react(),
      tailwindcss(),
      siteConfig(siteConfiguration),
      errorOverlay(),
      reactRefreshFallback(),
      componentKit({ storiesGlob: '/src/**/*.stories.{ts,tsx,js,jsx}' }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      host: '0.0.0.0',
      port: parseInt(process.env.PORT || '8443'),
      strictPort: true,
      watch: { ignored: ['**/config/**'] },
    },
    preview: {
      host: '0.0.0.0',
      port: parseInt(process.env.PORT || '8443'),
    },
  }
})