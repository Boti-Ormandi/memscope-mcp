import { AxeBuilder } from '@axe-core/playwright'
import { expect, test, type Locator, type Page } from '@playwright/test'
import { pages } from '../site-contract.js'

const origin = 'http://127.0.0.1:4323'
const modes = [
  { name: 'desktop light', width: 1280, height: 900, theme: 'light' },
  { name: 'desktop dark', width: 1280, height: 900, theme: 'dark' },
  { name: 'mobile light', width: 320, height: 800, theme: 'light' },
  { name: 'mobile dark', width: 320, height: 800, theme: 'dark' }
] as const

async function openInMode(page: Page, route: string, mode: (typeof modes)[number]) {
  await page.setViewportSize({ width: mode.width, height: mode.height })
  await page.goto(route)
  await page.evaluate((theme) => {
    localStorage.setItem('starlight-theme', theme)
    document.documentElement.dataset.theme = theme
  }, mode.theme)
  await expect(page.locator('html')).toHaveAttribute('data-theme', mode.theme)
}

async function tabTo(page: Page, target: Locator) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    await page.keyboard.press('Tab')
    if (await target.evaluate((element) => document.activeElement === element)) return
  }
  throw new Error('keyboard Tab did not reach the expected overflow region')
}

async function expectKeyboardScroll(page: Page, target: Locator) {
  await expect(target).toBeVisible()
  const before = await target.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
    scrollLeft: element.scrollLeft,
    overflowX: getComputedStyle(element).overflowX
  }))
  expect(before.scrollWidth).toBeGreaterThan(before.clientWidth)
  expect(['auto', 'scroll']).toContain(before.overflowX)
  await tabTo(page, target)
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('ArrowRight')
  await expect.poll(() => target.evaluate((element) => element.scrollLeft)).toBeGreaterThan(
    before.scrollLeft
  )
}

test.describe('all canonical pages', () => {
  for (const pageContract of pages) {
    for (const mode of modes) {
      test(`${pageContract.route} passes full Axe in ${mode.name} mode without page overflow`, async ({
        page
      }) => {
        await openInMode(page, pageContract.route, mode)
        await expect(
          page.getByRole('heading', { level: 1, name: pageContract.title })
        ).toBeVisible()
        await expect(page.locator('main')).toBeVisible()

        const layout = await page.evaluate(() => ({
          viewport: document.documentElement.clientWidth,
          document: document.documentElement.scrollWidth
        }))
        expect(layout.document).toBeLessThanOrEqual(layout.viewport + 1)

        const results = await new AxeBuilder({ page }).analyze()
        expect(results.violations).toEqual([])
      })
    }
  }
})

test.describe('search and keyboard interaction', () => {
  test('Pagefind finds scan_many and keyboard navigation opens its generated anchor', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('button', { name: 'Search' }).click()
    const search = page.getByRole('textbox', { name: 'Search' })
    await expect(search).toBeVisible({ timeout: 15_000 })
    await search.fill('scan_many')

    const result = page.locator('a[href*="/reference/mcp-tools/#scan_many"]').first()
    await expect(result).toBeVisible({ timeout: 15_000 })
    await result.focus()
    await page.keyboard.press('Enter')

    await expect(page).toHaveURL(/\/reference\/mcp-tools\/#scan_many$/)
    await expect(page.getByRole('heading', { level: 2, name: 'scan_many' })).toBeVisible()
  })

  test('the skip link and primary start action work from the keyboard', async ({ page }) => {
    await page.goto('/')
    await page.keyboard.press('Tab')
    const skip = page.getByRole('link', { name: 'Skip to content' })
    await expect(skip).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL(/#_top$/)

    const start = page.getByRole('link', { name: 'Get started' })
    await start.focus()
    await expect(start).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL(/\/get-started\/install\/$/)
    await expect(page.getByRole('heading', { level: 1, name: 'Install memscope-mcp' })).toBeVisible()
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`wide tool schema and plugin table scroll locally from the keyboard in ${theme} mode`, async ({
      page
    }) => {
      await page.setViewportSize({ width: 320, height: 800 })

      await page.goto('/reference/mcp-tools/')
      await page.evaluate((value) => {
        localStorage.setItem('starlight-theme', value)
        document.documentElement.dataset.theme = value
      }, theme)
      await expectKeyboardScroll(
        page,
        page.locator('main pre').filter({ hasText: '"end_exclusive"' }).first()
      )
      const toolLayout = await page.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        document: document.documentElement.scrollWidth
      }))
      expect(toolLayout.document).toBeLessThanOrEqual(toolLayout.viewport + 1)

      await page.goto('/plugins/upgrading/')
      await page.evaluate((value) => {
        localStorage.setItem('starlight-theme', value)
        document.documentElement.dataset.theme = value
      }, theme)
      await expectKeyboardScroll(page, page.locator('main table').first())
      const tableLayout = await page.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        document: document.documentElement.scrollWidth
      }))
      expect(tableLayout.document).toBeLessThanOrEqual(tableLayout.viewport + 1)
    })
  }

  test('historical tool guidance anchors remain browser-addressable beside generated schemas', async ({ page }) => {
    for (const anchor of [
      'configuration',
      'tool-list',
      'read-first-examples',
      'scan-boundary',
      'result-shape',
      'lua-and-scripts'
    ]) {
      await page.goto(`/reference/mcp-tools/#${anchor}`)
      await expect(page.locator(`main h2#${anchor}`)).toBeVisible()
      await expect(page).toHaveURL(new RegExp(`/reference/mcp-tools/#${anchor}$`))
    }
    await expect(page.locator('main h2#scan')).toBeVisible()
    await expect(page.locator('main h3').filter({ hasText: 'Input JSON schema' }).first()).toBeVisible()
  })

  test('hostile-looking tool text stays literal and noninteractive', async ({ page }) => {
    await page.goto('/reference/mcp-tools/')
    const paragraph = page
      .locator('main p')
      .filter({ hasText: 'Scripts live under $MEMSCOPE_HOME/scripts/<process>/<name>.lua.' })
      .first()

    await expect(paragraph).toBeVisible()
    await expect(paragraph).toContainText(
      'Scripts live under $MEMSCOPE_HOME/scripts/<process>/<name>.lua.'
    )
    await expect(paragraph.locator('a, code, img, script, style')).toHaveCount(0)
  })
})

test.describe('local production preview', () => {
  test('serves every canonical route and ordinary static discovery file', async ({ request }) => {
    for (const pageContract of pages) {
      const response = await request.get(pageContract.route)
      expect(response.status(), pageContract.route).toBe(200)
      expect(response.headers()['set-cookie'], pageContract.route).toBeUndefined()
    }

    for (const path of [
      '/robots.txt',
      '/llms.txt',
      '/favicon.svg',
      '/sitemap-index.xml',
      '/sitemap-0.xml'
    ]) {
      const response = await request.get(path)
      expect(response.status(), path).toBe(200)
    }

    for (const hostControl of ['/_redirects', '/_headers']) {
      const response = await request.get(hostControl)
      expect(response.status(), hostControl).toBe(404)
    }
  })

  test('serves the official 404 with full light, dark, desktop, and mobile Axe coverage', async ({
    page,
    request
  }) => {
    const response = await request.get('/this-route-does-not-exist/')
    expect(response.status()).toBe(404)

    for (const mode of modes) {
      await test.step(mode.name, async () => {
        await openInMode(page, '/this-route-does-not-exist/', mode)
        await expect(page.getByRole('heading', { level: 1, name: '404' })).toBeVisible()
        await expect(page.getByText('Page not found. Check the URL or try using the search bar.')).toBeVisible()
        const results = await new AxeBuilder({ page }).analyze()
        expect(results.violations).toEqual([])
      })
    }
  })

  test('loads representative pages and Pagefind without a remote runtime request', async ({ page }) => {
    const external: string[] = []
    page.on('request', (request) => {
      const requestOrigin = new URL(request.url()).origin
      if (requestOrigin !== origin) external.push(request.url())
    })

    await page.goto('/')
    await page.goto('/reference/mcp-tools/')
    await page.getByRole('button', { name: 'Search' }).click()
    const search = page.getByRole('textbox', { name: 'Search' })
    await search.fill('processes')
    await expect(page.getByRole('link', { name: /processes/i }).first()).toBeVisible({ timeout: 15_000 })

    expect(external).toEqual([])
  })
})
