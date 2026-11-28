// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import {
  adjacencyGraphs as commonAdjacencyGraphs,
  dictionary as commonDictionary,
} from "@zxcvbn-ts/language-common";
import { dictionary as enDictionary } from "@zxcvbn-ts/language-en";

export const MIN_PASSWORD_LENGTH = 12;
export const MIN_PASSWORD_SCORE = 3;

export interface ValidatePasswordOptions {
  readonly userInputs?: readonly string[];
}

export type PasswordValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "too_short" | "too_weak" };

let evaluator: ZxcvbnFactory | null = null;

function getEvaluator(): ZxcvbnFactory {
  if (evaluator === null) {
    evaluator = new ZxcvbnFactory({
      dictionary: {
        ...commonDictionary,
        ...enDictionary,
      },
      graphs: commonAdjacencyGraphs,
    });
  }
  return evaluator;
}

export function validatePassword(
  password: string,
  options?: ValidatePasswordOptions,
): PasswordValidationResult {
  const codePointLength = [...password].length;
  if (codePointLength < MIN_PASSWORD_LENGTH) {
    return { ok: false, reason: "too_short" };
  }

  if (password.trim().length === 0) {
    return { ok: false, reason: "too_weak" };
  }

  const userInputs = options?.userInputs ? [...options.userInputs] : [];
  const result = getEvaluator().check(password, userInputs);
  if (result.score < MIN_PASSWORD_SCORE) {
    return { ok: false, reason: "too_weak" };
  }

  return { ok: true };
}
