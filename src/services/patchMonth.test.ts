import test from 'node:test';
import assert from 'node:assert/strict';
import { msrcPatchMonth, otCurrentMonth, shiftPatchMonth } from './otPatchApi';

test('shared monthly controls retain year boundaries and Fortaleza reporting month', () => {
  assert.equal(shiftPatchMonth('2026-01', -1), '2025-12');
  assert.equal(shiftPatchMonth('2026-12', 1), '2027-01');
  assert.equal(otCurrentMonth(new Date('2026-11-01T02:00:00Z')), '2026-10');
  assert.equal(msrcPatchMonth('2026-Oct'), '2026-10');
  assert.equal(msrcPatchMonth('2026-Jan'), '2026-01');
  assert.equal(msrcPatchMonth('2026-Other'), '');
});
