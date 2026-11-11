import assert from 'node:assert/strict'
import { test } from 'node:test'
import { certificateDate, certificateTerm, defaultCertificateDate } from '../src/certificateDates.ts'
const expiry = Date.parse('2027-01-31T23:59:59Z') / 1000
const revoked = Date.parse('2026-11-08T12:00:00Z') / 1000

test('certificate dates stay on the selected UTC calendar day in any browser timezone', () => {
 const old=process.env.TZ
 try {for(const zone of ['Europe/Moscow','Pacific/Auckland','America/Los_Angeles']) {process.env.TZ=zone;assert.equal(certificateDate(expiry),'31.01.2027')}}
 finally {if(old===undefined)delete process.env.TZ;else process.env.TZ=old}
})
test('revoked profiles display revocation instead of a future validity claim',()=>{
 assert.equal(certificateTerm({status:'valid',not_after:expiry}),'Действует до 31.01.2027')
 assert.equal(certificateTerm({status:'revoked',not_after:expiry,revoked_at:revoked}),'Отозван 08.11.2026')
 assert.equal(certificateTerm({status:'revoked',not_after:expiry}),'Отозван')
 assert.equal(certificateTerm({status:'expired',not_after:expiry}),'Срок истёк 31.01.2027')
 assert.equal(certificateTerm({status:'pending',not_after:0}),'Ожидает выпуска')
 assert.equal(certificateDate(null),'—')
})

test('default certificate date is 825 UTC calendar days ahead across leap years and timezones', () => {
 const old = process.env.TZ
 try {
  for (const zone of ['Europe/Moscow', 'Pacific/Auckland', 'America/Los_Angeles']) {
   process.env.TZ = zone
   const now = new Date('2026-11-08T23:30:00Z')
   const original = now.toISOString()
   const expected = new Date(Date.UTC(2026, 10, 8) + 825 * 86400000).toISOString().slice(0, 10)
   assert.equal(defaultCertificateDate(now), expected)
   assert.equal(now.toISOString(), original, 'date calculation mutated its input')
  }
 } finally { if (old === undefined) delete process.env.TZ; else process.env.TZ = old }
})

test('default certificate date respects a shorter CA lifetime and never extends it', () => {
 const now = new Date('2026-11-10T23:30:00Z')
 assert.equal(defaultCertificateDate(now, '2026-12-31'), '2026-12-31')
 assert.equal(defaultCertificateDate(now, '2026-11-09'), '2026-11-09', 'an expired CA must not yield a future default')
 assert.equal(defaultCertificateDate(now, '2040-01-01'), defaultCertificateDate(now))
 assert.equal(defaultCertificateDate(now, defaultCertificateDate(now)), defaultCertificateDate(now))
 assert.equal(defaultCertificateDate(now, ''), defaultCertificateDate(now))
 assert.equal(defaultCertificateDate(now, undefined), defaultCertificateDate(now))
})
