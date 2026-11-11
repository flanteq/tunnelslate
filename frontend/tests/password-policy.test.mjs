import assert from 'node:assert/strict'
import { test } from 'node:test'
import { passwordLength, validNewPassword, passwordInputMaxLength } from '../src/passwordPolicy.ts'

test('password limits count Cyrillic and emoji as characters', () => {
  for (const char of ['a', 'я', '🔐']) {
    for (const length of [11, 12, 72, 73]) {
      const value = char.repeat(length)
      assert.equal(passwordLength(value), length)
      assert.equal(validNewPassword(value), length >= 12 && length <= 72)
    }
  }
  assert.ok('🔐'.repeat(72).length <= passwordInputMaxLength, 'HTML limit cuts off a valid password')
})
