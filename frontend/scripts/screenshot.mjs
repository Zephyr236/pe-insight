// UI 渲染验证脚本：截图并检查布局问题。用完即删。
import { chromium } from 'playwright'

const BASE = 'http://127.0.0.1:8080'
const OUT = 'C:/Users/user/Desktop/pe-insight/frontend/_shots'

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })

const problems = []
page.on('console', (msg) => {
  if (msg.type() === 'error') problems.push(`控制台错误: ${msg.text()}`)
})
page.on('pageerror', (err) => problems.push(`页面异常: ${err.message}`))

await page.goto(BASE, { waitUntil: 'networkidle' })
// /api/privacy 首次要拉起 PowerShell 读 Defender 设置，可能要几秒
await page.waitForSelector('.banner', { timeout: 20000 }).catch(() => {})
await page.waitForTimeout(600)

// 空状态
await page.screenshot({ path: `${OUT}/01-empty.png`, fullPage: false })
console.log('标题:', await page.title())
console.log('品牌:', (await page.locator('.brand__name').textContent())?.trim())
console.log('引擎条:', (await page.locator('.engines-strip__count').textContent())?.trim())

// 隐私横幅应当出现（本机 Defender 云保护已开启）
const banner = page.locator('.banner')
console.log('隐私横幅可见:', await banner.isVisible().catch(() => false))
if (await banner.count()) {
  console.log('横幅文本:', (await banner.textContent())?.replace(/\s+/g, ' ').trim().slice(0, 120))
}

// 提交一个扫描（用合成样本，能看到"恶意"结论）
// 注意：ransomware-sim 常被 Defender 实时防护直接隔离，所以用 credential-sim
const SAMPLE =
  process.env.SAMPLE ||
  'C:\\Users\\user\\Desktop\\pe-insight\\data\\inbox\\demo\\credential-sim.exe'
const input = page.locator('#path')
await input.fill(SAMPLE)
await page.locator('button[type=submit]').click()
console.log('已提交扫描，等待完成…')

// 等详情页出现
await page.waitForSelector('.detail__title', { timeout: 30000 })
// 注意签名是 waitForFunction(fn, arg, options)：options 是第三个参数。
// 写成第二个会被当成传给函数的 arg，超时设置静默失效。
await page.waitForFunction(
  () => !document.querySelector('.hero__sub')?.textContent?.includes('正在扫描'),
  null,
  { timeout: 300000 }, // 7 个引擎全跑完要几十秒（CAPA/Emsisoft 偏慢）
)
await page.waitForTimeout(1200)

await page.screenshot({ path: `${OUT}/02-detail-engines.png` })

const heroText = (await page.locator('.hero__label').textContent())?.trim()
console.log('英雄结论:', heroText)
console.log('网络隔离条:', (await page.locator('.netstrip').textContent())?.replace(/\s+/g, ' ').trim())

const tiles = await page.locator('.stat').allTextContents()
console.log('统计块:', tiles.map((t) => t.replace(/\s+/g, ' ').trim()).join(' | '))

const rows = await page.locator('.table tbody tr').allTextContents()
console.log('引擎行数:', rows.length)
rows.forEach((r) => console.log('  ', r.replace(/\s+/g, ' ').trim()))

// 静态分析页
await page.locator('.tabs__btn', { hasText: '静态分析' }).click()
await page.waitForTimeout(600)
await page.screenshot({ path: `${OUT}/03-static.png` })
console.log('静态节区行数:', await page.locator('.table tbody tr').count())

// 深色模式
await page.locator('button', { hasText: '深色' }).click()
await page.waitForTimeout(500)
await page.screenshot({ path: `${OUT}/04-dark.png` })

// 动态分析页
await page.locator('.tabs__btn', { hasText: '动态分析' }).click()
await page.waitForTimeout(600)
await page.screenshot({ path: `${OUT}/05-dynamic.png` })

// 检查横向溢出
const overflow = await page.evaluate(
  () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
)
console.log('横向溢出:', overflow)

await browser.close()

if (problems.length) {
  console.log('\n发现问题:')
  problems.forEach((p) => console.log('  -', p))
  process.exitCode = 1
} else {
  console.log('\n无控制台错误。')
}
