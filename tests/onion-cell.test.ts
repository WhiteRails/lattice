import { describe, expect, it } from 'vitest';
import * as crypto from 'crypto';
import {
  ONION_CELL_BODY_BYTES,
  ONION_CELL_BYTES,
  OnionCellCommand,
  OnionControlCommand,
  OnionStreamCommand,
  StrictSequence,
  addBackwardLayer,
  buildForwardOnion,
  buildForwardOnionDepth,
  decodeOnionControl,
  decodeOnionCell,
  decodeStreamFragment,
  encodeOnionCell,
  encodeOnionControl,
  encodeStreamFragment,
  fragmentStream,
  peelBackwardOnion,
  peelBackwardOnionDepth,
  peelForwardLayer,
} from '../node/onion-cell';
import type { OnionHopKeys } from '../node/onion-handshake';

function hop(): OnionHopKeys {
  return {
    forwardKey: crypto.randomBytes(32),
    backwardKey: crypto.randomBytes(32),
    forwardNonceSalt: crypto.randomBytes(4),
    backwardNonceSalt: crypto.randomBytes(4),
  };
}

describe('Lattice Onion v1 fixed cells', () => {
  it('encodes only exact 16 KiB cells', () => {
    const encoded = encodeOnionCell({
      command: OnionCellCommand.Relay,
      flags: 0,
      circuitId: 7,
      sequence: 9n,
      body: crypto.randomBytes(ONION_CELL_BODY_BYTES),
    });
    expect(encoded).toHaveLength(ONION_CELL_BYTES);
    expect(decodeOnionCell(encoded)).toMatchObject({ circuitId: 7, sequence: 9n, command: OnionCellCommand.Relay });
    expect(() => decodeOnionCell(encoded.subarray(1))).toThrow(/exactly/i);
  });

  it('peels three forward layers and adds/peels three backward layers', () => {
    const hops = [hop(), hop(), hop()];
    const contexts = [
      { circuitId: 11, sequence: 0n },
      { circuitId: 22, sequence: 0n },
      { circuitId: 33, sequence: 0n },
    ];
    const inner = encodeStreamFragment({
      command: OnionStreamCommand.Data,
      streamId: 123,
      fragmentIndex: 0,
      final: true,
      data: Buffer.from('payload visible only at endpoint'),
    });
    const outer = buildForwardOnion(inner, hops, contexts);
    expect(outer.toString('utf8')).not.toContain('payload visible only at endpoint');
    let wire = outer;
    let meaningful = Buffer.alloc(0);
    for (let index = 0; index < 3; index++) {
      const peeled = peelForwardLayer(wire, index, hops[index]!, contexts[index]!);
      meaningful = peeled.meaningful;
      wire = peeled.wireBody;
    }
    expect(decodeStreamFragment(meaningful).data.toString()).toBe('payload visible only at endpoint');

    wire = crypto.randomBytes(ONION_CELL_BODY_BYTES);
    inner.copy(wire);
    for (let index = 2; index >= 0; index--) wire = addBackwardLayer(wire, index, hops[index]!, contexts[index]!);
    expect(decodeStreamFragment(peelBackwardOnion(wire, hops, contexts)).data.toString()).toBe('payload visible only at endpoint');
  });

  it('rejects tampering, wrong AAD and replayed sequences', () => {
    const hops = [hop(), hop(), hop()];
    const contexts = [
      { circuitId: 1, sequence: 0n },
      { circuitId: 2, sequence: 0n },
      { circuitId: 3, sequence: 0n },
    ];
    const inner = encodeStreamFragment({ command: OnionStreamCommand.Data, streamId: 1, fragmentIndex: 0, final: true, data: Buffer.alloc(0) });
    const outer = buildForwardOnion(inner, hops, contexts);
    outer[100] ^= 1;
    expect(() => peelForwardLayer(outer, 0, hops[0]!, contexts[0]!)).toThrow();

    const valid = buildForwardOnion(inner, hops, contexts);
    expect(() => peelForwardLayer(valid, 0, hops[0]!, { ...contexts[0]!, circuitId: 99 })).toThrow();

    const sequence = new StrictSequence();
    sequence.claim(0n);
    expect(() => sequence.claim(0n)).toThrow(/unexpected/i);
    expect(() => sequence.claim(2n)).toThrow(/unexpected/i);
    sequence.claim(1n);
  });

  it('fragments and reassembles bounded stream data', () => {
    const data = crypto.randomBytes(40_000);
    const fragments = fragmentStream(44, data);
    expect(fragments.length).toBeGreaterThan(1);
    expect(fragments.at(-1)?.final).toBe(true);
    const decoded = fragments.map(fragment => decodeStreamFragment(encodeStreamFragment(fragment)));
    expect(Buffer.concat(decoded.map(fragment => fragment.data))).toEqual(data);
  });

  it('carries incremental EXTEND2 controls through one and two authenticated layers', () => {
    const hops = [hop(), hop()];
    const contexts = [{ circuitId: 41, sequence: 0n }, { circuitId: 42, sequence: 0n }];
    const plaintext = encodeOnionControl(
      OnionControlCommand.Extend2,
      { next_label: 'relay-c' },
      ONION_CELL_BODY_BYTES - 2 * 16,
    );
    let wire = buildForwardOnionDepth(plaintext, hops, contexts);
    const guard = peelForwardLayer(wire, 0, hops[0]!, contexts[0]!);
    expect(decodeOnionControl(guard.meaningful)).toBeNull();
    const middle = peelForwardLayer(guard.wireBody, 1, hops[1]!, contexts[1]!);
    expect(decodeOnionControl(middle.meaningful)).toEqual({
      command: OnionControlCommand.Extend2,
      value: { next_label: 'relay-c' },
    });

    wire = crypto.randomBytes(ONION_CELL_BODY_BYTES);
    plaintext.copy(wire);
    wire = addBackwardLayer(wire, 1, hops[1]!, contexts[1]!);
    wire = addBackwardLayer(wire, 0, hops[0]!, contexts[0]!);
    expect(decodeOnionControl(peelBackwardOnionDepth(wire, hops, contexts))?.command).toBe(OnionControlCommand.Extend2);
  });
});
