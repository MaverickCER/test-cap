// Fails when a ZAP report holds any alert of medium risk or above (the plan's bar: "ZAP reports nothing at medium or
// above"), and prints every alert, low and informational ones included, so the log shows what the scan saw.
//
// Usage: node ci/zap/check-report.mjs <report.json>...   (ZAP's -J traditional JSON report)
import { readFileSync } from "node:fs"

const RISK = ["informational", "low", "medium", "high"]
let failed = false
for (const path of process.argv.slice(2)) {
  const report = JSON.parse(readFileSync(path, "utf8"))
  const alerts = (report.site ?? []).flatMap((site) => site.alerts ?? [])
  console.log(`${path}: ${String(alerts.length)} alert type(s)`)
  for (const alert of alerts) {
    const risk = Number(alert.riskcode)
    const where = (alert.instances ?? []).slice(0, 3).map((each) => `${each.method} ${each.uri}`)
    console.log(`  [${RISK[risk] ?? risk}] ${alert.pluginid} ${alert.alert}: ${where.join(", ")}`)
    if (risk >= 2) failed = true
  }
}
if (failed) {
  console.error("ZAP found an alert of medium risk or above.")
  process.exit(1)
}
