// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

const utf8Encoder = new TextEncoder();

function compareCodeUnits(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function serializeCanonical(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number": {
      if (!Number.isFinite(value)) {
        throw new TypeError("Cannot canonicalize non-finite number");
      }
      return Object.is(value, -0) ? "0" : JSON.stringify(value);
    }
    case "string":
      return JSON.stringify(value);
    case "undefined":
    case "function":
    case "symbol":
    case "bigint":
      throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
    case "object": {
      if (ancestors.has(value)) {
        throw new TypeError("Cannot canonicalize circular reference");
      }

      if (Array.isArray(value)) {
        ancestors.add(value);
        try {
          const items: string[] = [];
          for (let i = 0; i < value.length; i++) {
            items.push(serializeCanonical(value[i], ancestors));
          }
          return `[${items.join(",")}]`;
        } finally {
          ancestors.delete(value);
        }
      }

      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError("Cannot canonicalize non-plain object");
      }

      ancestors.add(value);
      try {
        const record = value as Record<string, unknown>;
        const keys = Object.keys(record)
          .filter((k) => record[k] !== undefined)
          .sort(compareCodeUnits);

        const entries: string[] = [];
        for (const key of keys) {
          entries.push(`${JSON.stringify(key)}:${serializeCanonical(record[key], ancestors)}`);
        }
        return `{${entries.join(",")}}`;
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
  }
}

export function canonicalize(value: unknown): Uint8Array {
  return utf8Encoder.encode(serializeCanonical(value, new Set()));
}
