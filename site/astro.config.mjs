import starlight from '@astrojs/starlight'
import { defineConfig } from 'astro/config'
import { cloudflarePages, mcpSite } from 'mcp-site-platform'

const sidebar = [
  { label: 'Home', link: '/' },
  {
    label: 'Get started',
    items: [
      { label: 'Install memscope-mcp', link: '/get-started/install/' },
      { label: 'Configure an MCP client', link: '/get-started/configure-client/' },
      { label: 'Perform a first session', link: '/get-started/first-session/' },
      { label: 'Permissions and local data', link: '/get-started/permissions-and-data/' }
    ]
  },
  {
    label: 'Guides',
    items: [
      { label: 'Discover and attach', link: '/guides/discover-and-attach/' },
      { label: 'Read and write memory', link: '/guides/read-and-write-memory/' },
      { label: 'Scan target memory', link: '/guides/scan-memory/' },
      { label: 'Use saved scripts', link: '/guides/saved-scripts/' },
      { label: 'Inspect before attach', link: '/guides/inspect-before-attach/' },
      { label: 'Capture function calls', link: '/guides/capture-function-calls/' },
      { label: 'Use plugins', link: '/guides/use-plugins/' }
    ]
  },
  {
    label: 'Plugins',
    items: [
      { label: 'Plugin overview', link: '/plugins/overview/' },
      { label: 'Author a plugin', link: '/plugins/authoring/' },
      { label: 'Plugin lifecycle and contract', link: '/plugins/lifecycle-and-contract/' },
      { label: 'Upgrade plugins', link: '/plugins/upgrading/' },
      { label: 'Troubleshoot plugins', link: '/plugins/troubleshooting/' },
      { label: 'IL2CPP plugin', link: '/plugins/il2cpp/' },
      { label: 'Netcap plugin', link: '/plugins/netcap/' }
    ]
  },
  {
    label: 'Reference',
    items: [
      { label: 'MCP tool reference', link: '/reference/mcp-tools/' },
      { label: 'Lua reference', link: '/reference/lua/' },
      { label: 'Scanning reference', link: '/reference/scanning/' },
      { label: 'Plugin API reference', link: '/reference/plugin-api/' },
      { label: 'CLI and paths', link: '/reference/cli-and-paths/' },
      { label: 'Errors and status', link: '/reference/errors-and-status/' }
    ]
  },
  {
    label: 'Concepts',
    items: [
      { label: 'Architecture', link: '/concepts/architecture/' },
      { label: 'Session lifecycle', link: '/concepts/session-lifecycle/' },
      { label: 'Extension composition', link: '/concepts/extension-composition/' },
      { label: 'Security model', link: '/concepts/security-model/' }
    ]
  },
  {
    label: 'Support',
    items: [
      { label: 'Troubleshooting', link: '/support/troubleshooting/' },
      { label: 'Compatibility', link: '/support/compatibility/' },
      { label: 'Security support', link: '/support/security/' }
    ]
  },
  { label: 'Contribute', link: '/contribute/' },
  { label: 'Releases', link: '/releases/' }
]

export default defineConfig({
  site: 'https://memscope.esrc.dev',
  output: 'static',
  trailingSlash: 'always',
  build: { format: 'directory' },
  integrations: [
    starlight({
      title: 'Memscope',
      description: 'Windows process-memory MCP documentation for reverse engineering and live-process research.',
      favicon: '/favicon.svg',
      social: [
        {
          icon: 'github',
          label: 'Memscope source on GitHub',
          href: 'https://github.com/Boti-Ormandi/memscope-mcp'
        }
      ],
      plugins: [mcpSite()],
      customCss: ['./src/styles/memscope.css'],
      sidebar,
      pagefind: true,
      lastUpdated: false,
      pagination: true
    }),
    cloudflarePages({ derivedNoSlashRedirects: true })
  ]
})
