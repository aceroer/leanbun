export function renderJsonReport(report: unknown): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
