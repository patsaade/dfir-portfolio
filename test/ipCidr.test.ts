import { describe, it, expect } from 'vitest';
import { getIpCidrQuestion } from '../src/data/drills/ipCidr';

const TOTAL = 10;

describe('getIpCidrQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < TOTAL; i++) {
      const a = getIpCidrQuestion(i);
      const b = getIpCidrQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getIpCidrQuestion(TOTAL)).not.toThrow();
    expect(getIpCidrQuestion(TOTAL).prompt).toBe(getIpCidrQuestion(0).prompt);
  });

  it('no question is multiple choice — every question is free-text recall', () => {
    for (let i = 0; i < TOTAL; i++) {
      const q = getIpCidrQuestion(i);
      expect(q.answerType).toBe('text');
      expect(q.choices).toBeUndefined();
    }
  });

  it('every question has a non-empty prompt/explanation and a working grade() that accepts its own correctAnswer', () => {
    for (let i = 0; i < TOTAL; i++) {
      const q = getIpCidrQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(typeof q.grade).toBe('function');
      expect(q.grade!(q.correctAnswer), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
      expect(q.grade!('definitely-wrong'), `question ${i} grade() accepted an obviously wrong answer`).toBe(false);
    }
  });

  it('network/broadcast address questions grade leading-zero and whitespace variants the same as the canonical form', () => {
    const network = getIpCidrQuestion(0); // 192.168.4.130/26
    expect(network.correctAnswer).toBe('192.168.4.128');
    expect(network.grade!(' 192.168.4.128 ')).toBe(true);
    expect(network.grade!('192.168.4.129')).toBe(false);

    const broadcast = getIpCidrQuestion(2); // 10.20.30.0/22
    expect(broadcast.correctAnswer).toBe('10.20.31.255');
    expect(broadcast.grade!('10.20.31.255')).toBe(true);
  });

  it('usable-host and subnet-count questions strip non-digit characters before comparing', () => {
    const usable = getIpCidrQuestion(5); // 172.16.5.0/27 -> 30 usable hosts
    expect(usable.correctAnswer).toBe('30');
    expect(usable.grade!('30 hosts')).toBe(true);
    expect(usable.grade!('29')).toBe(false);
  });

  it('the three category-recognition questions (100.64.0.0/10, 169.254.0.0/16, 192.0.2.0/24) accept both the hyphenated id and the human label, case/hyphen-insensitively', () => {
    const cgnat = getIpCidrQuestion(1);
    expect(cgnat.correctAnswer).toBe('Shared address space (CGNAT)');
    expect(cgnat.grade!('shared-address-space')).toBe(true);
    expect(cgnat.grade!('Shared Address Space')).toBe(true);
    expect(cgnat.grade!('private-use')).toBe(false);

    const linkLocal = getIpCidrQuestion(4);
    expect(linkLocal.correctAnswer).toBe('Link-local');
    expect(linkLocal.grade!('link local')).toBe(true);
    expect(linkLocal.grade!('Link-Local')).toBe(true);

    const documentation = getIpCidrQuestion(7);
    expect(documentation.correctAnswer).toBe('Documentation');
    expect(documentation.grade!('documentation')).toBe(true);
    expect(documentation.grade!('multicast')).toBe(false);
  });

  it('smallest-prefix question grades the numeric prefix regardless of the leading slash', () => {
    const q = getIpCidrQuestion(6); // smallest prefix covering >= 100 hosts
    expect(q.correctAnswer).toBe('/25');
    expect(q.grade!('/25')).toBe(true);
    expect(q.grade!('25')).toBe(true);
    expect(q.grade!('/26')).toBe(false);
  });
});
