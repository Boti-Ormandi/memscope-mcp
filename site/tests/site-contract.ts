export interface SitePage {
  route: string
  title: string
  description: string
}

export const pages: readonly SitePage[] = [
  {
    route: '/',
    title: 'memscope-mcp',
    description: 'Windows process-memory MCP server for reverse engineering and live-process research.'
  },
  {
    route: '/get-started/install/',
    title: 'Install memscope-mcp',
    description: 'Prepare a Windows x64 host and install the memscope-mcp package.'
  },
  {
    route: '/get-started/configure-client/',
    title: 'Configure an MCP client',
    description: 'Start memscope-mcp over stdio from an MCP-compatible client.'
  },
  {
    route: '/get-started/first-session/',
    title: 'Perform a first session',
    description: 'Attach to a selected process and begin with a bounded read-only inspection.'
  },
  {
    route: '/get-started/permissions-and-data/',
    title: 'Permissions and local data',
    description: 'Understand Windows permissions, MEMSCOPE_HOME, logs, scripts, plugins, and recordings.'
  },
  {
    route: '/guides/discover-and-attach/',
    title: 'Discover and attach',
    description: 'Select an exact process and inspect its immutable module snapshot.'
  },
  {
    route: '/guides/read-and-write-memory/',
    title: 'Read and write memory',
    description: 'Read typed target memory and make verified writes.'
  },
  {
    route: '/guides/scan-memory/',
    title: 'Scan target memory',
    description: 'Run strict bounded AOB, string, pointer, and batch scans.'
  },
  {
    route: '/guides/saved-scripts/',
    title: 'Use saved scripts',
    description: 'Store and run Lua workflows under the data root.'
  },
  {
    route: '/guides/inspect-before-attach/',
    title: 'Inspect before attach',
    description: 'Read bounded PEB process information without populating the debug session.'
  },
  {
    route: '/guides/capture-function-calls/',
    title: 'Capture function calls',
    description: 'Use inline hooks and bounded target-side ring buffers.'
  },
  {
    route: '/guides/use-plugins/',
    title: 'Use plugins',
    description: 'Activate opt-in IL2CPP, Netcap, or local Python plugins.'
  },
  {
    route: '/plugins/overview/',
    title: 'Plugin overview',
    description: 'Understand the explicit activated-file plugin boundary.'
  },
  {
    route: '/plugins/authoring/',
    title: 'Author a plugin',
    description: 'Create a session-bound plugin with atomic Lua registration.'
  },
  {
    route: '/plugins/lifecycle-and-contract/',
    title: 'Plugin lifecycle and contract',
    description: 'Compose plugin mappings atomically before process attach and detach callbacks run.'
  },
  {
    route: '/plugins/upgrading/',
    title: 'Upgrade plugins',
    description: 'Keep activated plugins on the current session-bound ExtensionContext contract.'
  },
  {
    route: '/plugins/troubleshooting/',
    title: 'Troubleshoot plugins',
    description: 'Diagnose isolated plugin failures without bypassing composition boundaries.'
  },
  {
    route: '/plugins/il2cpp/',
    title: 'IL2CPP plugin',
    description: 'Read common Unity IL2CPP structures and keep thread-local calls in one sequence.'
  },
  {
    route: '/plugins/netcap/',
    title: 'Netcap plugin',
    description: 'Capture Winsock traffic and manage canonical recordings.'
  },
  {
    route: '/reference/mcp-tools/',
    title: 'MCP tool reference',
    description: 'Installed-wheel reference for the exact 11-tool stdio surface.'
  },
  {
    route: '/reference/lua/',
    title: 'Lua reference',
    description: 'Core Lua 5.4 functions exposed through the private session-bound runtime.'
  },
  {
    route: '/reference/scanning/',
    title: 'Scanning reference',
    description: 'Strict scan requests, scopes, continuation, statuses, and diagnostics.'
  },
  {
    route: '/reference/plugin-api/',
    title: 'Plugin API reference',
    description: 'Supported PluginBase, LuaExtension, and ExtensionContext contracts.'
  },
  {
    route: '/reference/cli-and-paths/',
    title: 'CLI and paths',
    description: 'Console commands and exact MEMSCOPE_HOME data locations.'
  },
  {
    route: '/reference/errors-and-status/',
    title: 'Errors and status',
    description: 'Structured failures, scan termination, Lua cancellation, and plugin diagnostics.'
  },
  {
    route: '/concepts/architecture/',
    title: 'Architecture',
    description: 'The Windows x64 stdio, session, Lua, scanning, and plugin architecture.'
  },
  {
    route: '/concepts/session-lifecycle/',
    title: 'Session lifecycle',
    description: 'Attachment identity, module generations, leases, reconnect, and cleanup.'
  },
  {
    route: '/concepts/extension-composition/',
    title: 'Extension composition',
    description: 'Transactional core and plugin registration into one ready Lua namespace.'
  },
  {
    route: '/concepts/security-model/',
    title: 'Security model',
    description: 'Target process effects, plugin execution, and local data locations.'
  },
  {
    route: '/support/troubleshooting/',
    title: 'Troubleshooting',
    description: 'Resolve startup, attach, memory, scan, Lua, plugin, and Netcap failures.'
  },
  {
    route: '/support/compatibility/',
    title: 'Compatibility',
    description: 'Supported Windows, Python, MCP, Lua, data, and plugin boundaries.'
  },
  {
    route: '/support/security/',
    title: 'Security support',
    description: 'Report unintended security behavior through the private advisory route.'
  },
  {
    route: '/contribute/',
    title: 'Contribute',
    description: 'Set up a Windows development environment and contribute focused changes.'
  },
  {
    route: '/releases/',
    title: 'Releases',
    description: 'Current release guidance and links to version-specific GitHub Release history.'
  }
] as const

export const toolNames = [
  'processes',
  'attach',
  'modules',
  'read',
  'write',
  'dump',
  'chain',
  'scan',
  'scan_many',
  'lua',
  'scripts'
] as const

export function routeFile(route: string): string {
  return route === '/' ? 'index.html' : `${route.slice(1)}index.html`
}
