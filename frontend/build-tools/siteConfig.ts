import type { HtmlTagDescriptor, Plugin } from 'vite'

export type SiteConfiguration = {
  title?: string
  description?: string
  language?: string
  robots?: { index?: boolean }
  icons?: { icon?: string }
  openGraph?: { image?: string }
  analytics?: { googleAnalyticsId?: string }
  customScripts?: { headStart?: string; headEnd?: string; bodyStart?: string; bodyEnd?: string }
  accessibility?: { addBypassLinks?: boolean }
}

export default function siteConfig(config: SiteConfiguration): Plugin {
  function sanitizeHtmlValue(value: string | undefined): string {
    return value?.replace(/[^a-zA-Z0-9_-]/g, '') || ''
  }
  function escapeHtmlText(value: string): string {
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  }
  function replaceHtmlCommentSlot(html: string, slotName: string, content: string): string {
    return html.replace(`<!-- ${slotName} -->`, content)
  }

  const title = config.title ?? "React App"
  const description = config.description ?? ''
  const favicon = config.icons?.icon ?? ''
  const socialImage = config.openGraph?.image ?? ''
  const language = sanitizeHtmlValue(config.language) || 'en'
  const googleAnalyticsId = sanitizeHtmlValue(config.analytics?.googleAnalyticsId)
  const headStart = config.customScripts?.headStart ?? ''
  const headEnd = config.customScripts?.headEnd ?? ''
  const bodyStart = config.customScripts?.bodyStart ?? ''
  const bodyEnd = config.customScripts?.bodyEnd ?? ''
  const robotsTxt = config.robots?.index === false ? 'User-agent: *\nDisallow: /\n' : ''

  return {
    name: 'app-site-configuration',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (!robotsTxt || req.url?.split('?')[0] !== '/robots.txt') return next()
        res.setHeader('Content-Type', 'text/plain; charset=utf-8')
        res.end(robotsTxt)
      })
    },
    generateBundle() {
      if (!robotsTxt) return
      this.emitFile({ type: 'asset', fileName: 'robots.txt', source: robotsTxt })
    },
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        let result = html
        result = replaceHtmlCommentSlot(result, 'app:lang', language)
        result = replaceHtmlCommentSlot(result, 'app:title', escapeHtmlText(title))
        result = replaceHtmlCommentSlot(result, 'app:head-start', headStart)
        result = replaceHtmlCommentSlot(result, 'app:head-end', headEnd)
        result = replaceHtmlCommentSlot(result, 'app:body-start', bodyStart)
        result = replaceHtmlCommentSlot(result, 'app:body-end', bodyEnd)

        const tags: HtmlTagDescriptor[] = []
        if (description) tags.push({ tag: 'meta', attrs: { name: 'description', content: description }, injectTo: 'head' })
        if (config.robots?.index === false) tags.push({ tag: 'meta', attrs: { name: 'robots', content: 'noindex, nofollow' }, injectTo: 'head' })
        if (favicon) tags.push({ tag: 'link', attrs: { rel: 'icon', href: favicon }, injectTo: 'head' })
        if (title) tags.push({ tag: 'meta', attrs: { property: 'og:title', content: title }, injectTo: 'head' })
        if (description) tags.push({ tag: 'meta', attrs: { property: 'og:description', content: description }, injectTo: 'head' })
        if (socialImage) {
          tags.push(
            { tag: 'meta', attrs: { property: 'og:image', content: socialImage }, injectTo: 'head' },
            { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' }, injectTo: 'head' },
            { tag: 'meta', attrs: { name: 'twitter:image', content: socialImage }, injectTo: 'head' }
          )
        }
        
        return { html: result, tags }
      },
    },
  }
}