import * as crypto from 'crypto';
import { describe, expect, it } from 'vitest';
import {
  ONION_CELL_BYTES,
  decodeOnionCell,
  decodeOnionControl,
  decodeStreamFragment,
} from '../node/onion-cell';
import { decodeOnionWirePayload } from '../node/onion-wire';

describe('bounded onion binary parser fuzz corpus', () => {
  it('rejects arbitrary/truncated frames without escaping parser errors', () => {
    for (let index = 0; index < 2_000; index++) {
      const length = index % (ONION_CELL_BYTES + 2);
      const sample = crypto.randomBytes(length);
      expect(() => {
        try { decodeOnionCell(sample); } catch (error) { expect(error).toBeInstanceOf(Error); }
        try { decodeOnionControl(sample); } catch (error) { expect(error).toBeInstanceOf(Error); }
        try { decodeStreamFragment(sample); } catch (error) { expect(error).toBeInstanceOf(Error); }
        try { decodeOnionWirePayload(sample); } catch (error) { expect(error).toBeInstanceOf(Error); }
      }).not.toThrow();
    }
  });

  it('does not accept random exact-size frames as valid cells', () => {
    let accepted = 0;
    for (let index = 0; index < 256; index++) {
      try { decodeOnionCell(crypto.randomBytes(ONION_CELL_BYTES)); accepted++; } catch {}
    }
    expect(accepted).toBe(0);
  });
});
