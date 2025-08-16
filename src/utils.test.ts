import { strict as assert } from 'node:assert'
import { suite, test } from 'node:test'

import { isDomain, validatedTld } from './utils.ts'

suite('isDomain()', () => {
	test('invalid domains', function () {
		assert.equal(false, isDomain(''), 'empty')
		assert.equal(false, isDomain('c'), 'too short')
		assert.equal(false, isDomain('c om'), 'contains space')
		assert.equal(false, isDomain('domain'), 'no tld')
		assert.equal(false, isDomain('-example.com'), 'starts with hyphen')
		assert.equal(false, isDomain('example.com1'), 'tld contains number')
		assert.throws(() => validatedTld('clearlyinvalidtldbecasuethisistoooooooooooooloooooooooooooooooong.com'), 'too long')
	})

	test('valid domain string', function () {
		assert.ok(isDomain('example.com'))
		assert.ok(isDomain('.example.com.'))
		assert.ok(isDomain('youtu.be'))
		assert.ok(isDomain('blog.google'))
	})
})

suite('validatedTld()', () => {
	test('invalid TLDs', function () {
		assert.throws(() => validatedTld(''), 'empty')
		assert.throws(() => validatedTld('c'), 'too short')
		assert.throws(() => validatedTld('c om'), 'contains space')
		assert.throws(() => validatedTld('c,om'), 'contains comma')
		assert.throws(() => validatedTld('-abc'), 'starts with hyphen')
		assert.throws(() => validatedTld('abc-'), 'ends with hyphen')
		assert.throws(() => validatedTld('com1'), 'contains number')
		assert.throws(() => validatedTld('clearlyinvalidtldbecasuethisistoooooooooooooloooooooooooooooooong'), 'too long')
	})

	test('valid - TLDs', function () {
		assert.equal(validatedTld('.com'), 'com')
		assert.equal(validatedTld('org.'), 'org')
		assert.equal(validatedTld('AI'), 'ai')
		assert.equal(validatedTld('.nyc'), 'nyc')
	})

	test('valid - SLDs', function () {
		assert.equal(validatedTld('.co.uk'), 'co.uk')
	})

	test('valid - IDN', function () {
		assert.equal(validatedTld('xn--zckzah'), 'xn--zckzah')
		assert.equal(validatedTld('テスト'), 'テスト')
		assert.equal(validatedTld('.香港'), '香港')
	})
})
