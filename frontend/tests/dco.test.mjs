import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import { dcoLabel } from '../src/dco.ts'
import { setLanguage } from '../src/i18n.ts'

afterEach(() => setLanguage('ru'))

test('DCO status labels distinguish actual use, disabled settings, unavailable and unknown state', () => {
  setLanguage('en')
  assert.equal(dcoLabel({ state: 'active' }), 'Active')
  assert.equal(dcoLabel({ state: 'disabled' }), 'Disabled')
  assert.equal(dcoLabel({ state: 'unavailable' }), 'Not in use')
  assert.equal(dcoLabel(), 'Unknown')
  setLanguage('ru')
  assert.equal(dcoLabel({ state: 'active' }), 'Работает')
  assert.equal(dcoLabel({ state: 'disabled' }), 'Выключено')
  assert.equal(dcoLabel({ state: 'unavailable' }), 'Не используется')
})
