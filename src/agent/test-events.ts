// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { PublicKey, SigningKeyPair } from "../crypto";
import { openAgentEvent } from "../protocol";

/**
 * Test helper: opens an agent event and exposes the carried `data` as `body`,
 * so assertions can ignore the `{ in_reply_to, data }` envelope.
 */
export function openTestEvent(
  message: unknown,
  agentPublicKey: PublicKey,
  recipient: SigningKeyPair,
) {
  const opened = openAgentEvent(message, agentPublicKey, recipient);
  return { header: opened.header, inReplyTo: opened.inReplyTo, body: opened.data };
}
