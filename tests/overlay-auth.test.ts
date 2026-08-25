import { describe, expect, it } from 'vitest';
import { parseOverlayMessage, signOverlayMessage, verifyOverlayMessage, OverlayMessage } from '../node/message';

function message(): OverlayMessage {
  return {
    id: 'msg-1',
    type: 'request',
    source: 'bot1',
    destination: 'lp://echo.lattice',
    payload: {
      method: 'GET',
      url: '/echo.ping',
      headers: { host: 'echo.lattice' },
    },
    trace: ['entry'],
  };
}

describe('Overlay message authentication', () => {
  it('verifies signed messages and allows trace extension', () => {
    const signed = signOverlayMessage(message(), 'secret');
    signed.trace.push('relay');
    expect(verifyOverlayMessage(signed, 'secret')).toBe(true);
  });

  it('rejects payload tampering', () => {
    const signed = signOverlayMessage(message(), 'secret');
    const tampered = {
      ...signed,
      payload: { ...signed.payload, url: '/repo.delete' },
    };
    expect(verifyOverlayMessage(tampered, 'secret')).toBe(false);
  });

  it('rejects unsigned messages', () => {
    expect(verifyOverlayMessage(message(), 'secret')).toBe(false);
  });

  it('keeps authentication valid after wire serialization with optional fields absent', () => {
    const signed = signOverlayMessage({
      ...message(),
      source_node_label: undefined,
      source_node_role: undefined,
    }, 'secret');
    const received = parseOverlayMessage(JSON.stringify(signed));
    expect(received).not.toBeNull();
    expect(verifyOverlayMessage(received!, 'secret')).toBe(true);
  });
});
