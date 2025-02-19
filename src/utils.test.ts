import { strict as assert } from 'node:assert'
import { suite, test } from 'node:test'

import { validatedTld } from './utils.ts'

suite('validatedTld()', () => {
	test('invalid TLDs', function() {
		assert.throws(() => validatedTld(''), 'empty')
		assert.throws(() => validatedTld('c'), 'too short')
		assert.throws(() => validatedTld('c om'), 'contains space')
		assert.throws(() => validatedTld('c,om'), 'contains comma')
		assert.throws(() => validatedTld('-abc'), 'starts with hyphen')
		assert.throws(() => validatedTld('abc-'), 'ends with hyphen')
		assert.throws(() => validatedTld('com1'), 'contains number')
		assert.throws(() => validatedTld('clearlyinvalidtldbecasuethisistoooooooooooooloooooooooooooooooong'), 'too long')
	})

	test('valid - TLDs', function() {
		assert.equal(validatedTld('.com'), 'com')
		assert.equal(validatedTld('org.'), 'org')
		assert.equal(validatedTld('AI'), 'ai')
		assert.equal(validatedTld('.nyc'), 'nyc')
	})

	test('valid - SLDs', function() {
		assert.equal(validatedTld('.co.uk'), 'co.uk')
	})

	test('valid - IDN', function() {
		assert.equal(validatedTld('xn--zckzah'), 'xn--zckzah')
		assert.equal(validatedTld('テスト'), 'テスト')
		assert.equal(validatedTld('.香港'), '香港')
	})
})
