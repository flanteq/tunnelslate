import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatBytes, formatDuration } from '../src/statistics.ts'
import { setLanguage } from '../src/i18n.ts'
test('statistics format binary byte units without losing small traffic', () => {
 setLanguage('en')
 for (const [bytes,text] of [[0,'0 B'],[1,'1 B'],[1023,'1,023 B'],[1024,'1 KiB'],[1536,'1.5 KiB'],[1024**3,'1 GiB']]) assert.equal(formatBytes(bytes),text)
})
test('statistics duration preserves summed days instead of wrapping at 24 hours', () => {
 setLanguage('en')
 assert.equal(formatDuration(0),'0m 0s');assert.equal(formatDuration(65),'1m 5s');assert.equal(formatDuration(3660),'1h 1m');assert.equal(formatDuration(86400*12+3660),'12d 1h 1m')
 setLanguage('ru');assert.equal(formatDuration(86400+3660),'1 д 1 ч 1 мин')
})
