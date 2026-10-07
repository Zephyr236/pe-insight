/**
 * 生成 README / 文档用的界面截图。
 *
 *   node scripts/docs-shots.mjs
 *
 * 输出到 ../docs/screenshots/，这些图会被提交进版本库，
 * 所以脚本刻意用固定视口、固定主题，保证每次生成的图一致。
 *
 * ⚠ 必须指向一个**干净的实例**，不能指向你日常用的那个。
 *   这个脚本会把界面连同左侧的历史记录一起截进去，如果历史里
 *   有你真实分析过的样本名，那些名字就会被公开。
 *
 *   正确做法：用 tools/prep_doc_shots.py 在 8090 端口起一个独立数据目录
 *   的实例，然后指向它。
 */
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const BASE = process.env.PEINSIGHT_SHOT_BASE || 'http://127.0.0.1:8090'
const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs', 'screenshots')
mkdirSync(OUT, { recursive: true })

const browser = await chromium.launch()
const page = await browser.newPage({
  viewport: { width: 1500, height: 940 },
  deviceScaleFactor: 2, // 高清图，README 里缩放后依然清晰
})

const shot = async (name) => {
  await page.screenshot({ path: join(OUT, `${name}.png`) })
  console.log(`  ✓ ${name}.png`)
}

await page.goto(BASE, { waitUntil: 'networkidle' })
await page.waitForSelector('.banner', { timeout: 20000 }).catch(() => {})
await page.waitForTimeout(600)

// ---- 1. 扫描列表 + 提交区 ----------------------------------------------
await shot('01-home')

// ---- 2. 选中最近一次扫描，展示结论与多引擎结果 --------------------------
const first = page.locator('.list__item').first()
if ((await first.count()) > 0) {
  await first.click()
  await page.waitForSelector('.detail__title', { timeout: 20000 })
  await page.waitForFunction(
    () => !document.querySelector('.hero__sub')?.textContent?.includes('正在扫描'),
    null,
    { timeout: 300000 },
  )
  await page.waitForTimeout(800)
  await shot('02-verdict-and-engines')

  const tabs = ['静态分析', '动态分析']
  const names = ['03-static', '04-dynamic']
  for (let i = 0; i < tabs.length; i++) {
    const btn = page.locator('.tabs__btn', { hasText: tabs[i] })
    if ((await btn.count()) === 0) continue
    await btn.click()
    await page.waitForTimeout(700)
    await shot(names[i])
  }

  // ---- 5. 深色模式下的结论页 ------------------------------------------
  const themeBtn = page.locator('button', { hasText: '深色' })
  if ((await themeBtn.count()) > 0) {
    await themeBtn.click()
    await page.waitForTimeout(400)
    const enginesTab = page.locator('.tabs__btn', { hasText: '引擎结果' })
    if ((await enginesTab.count()) > 0) await enginesTab.click()
    await page.waitForTimeout(600)
    await shot('05-dark-mode')
  }
} else {
  console.log('  ! 没有扫描记录，跳过详情页截图')
}

await browser.close()
console.log(`\n完成，输出目录：${OUT}`)
