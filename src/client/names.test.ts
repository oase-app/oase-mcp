import test from "node:test";
import assert from "node:assert/strict";
import { OaseClient } from "./oaseClient.js";

/** Client with network and crypto stubbed: bundles are {t: "<plain>"}. */
function stubbed(roster: () => unknown[], chat: unknown[]) {
  const calls: string[] = [];
  const c = new OaseClient({ oases: {}, displayName: "x" } as never) as any;
  c.getMyParticipantId = async () => "p-me";
  c.decrypt = async (b: { t: string }) => b.t;
  c.authed = async (_m: string, path: string) => {
    calls.push(path);
    if (path.includes("participants/projections/list/evolve")) {
      return { collection: roster() };
    }
    return { to_version: "1", collection: chat };
  };
  return { c: c as OaseClient, calls };
}
const person = (id: string, name: string) => ({
  participant_id: id,
  participant_name_cipher_bundle: { t: name },
});
const msg = (from: string, reactBy: string[]) => ({
  id: "m1",
  type: "message",
  participant_id: from,
  chat_id: "o",
  version: "1",
  body_cipher_bundle: { t: "hi" },
  reactions: reactBy.map((by) => ({
    participant_id: by,
    reaction_cipher_bundle: { t: "👍" },
  })),
});

test("reactor and sender names are resolved", async () => {
  const { c } = stubbed(
    () => [person("p-a", "Alice"), person("p-me", "Bot")],
    [msg("p-a", ["p-a", "p-me"])],
  );
  const { messages } = await c.chatEvolve("o", "");
  assert.equal(messages[0]!.fromName, "Alice");
  assert.deepEqual(
    messages[0]!.reactions.map((r) => r.name),
    ["Alice", "Bot"],
  );
});

test("unknown participant falls back to no name", async () => {
  const { c } = stubbed(() => [person("p-a", "Alice")], [msg("p-a", ["p-x"])]);
  const { messages } = await c.chatEvolve("o", "");
  assert.equal(messages[0]!.reactions[0]!.name, undefined);
  assert.equal(messages[0]!.reactions[0]!.emoji, "👍");
});

test("cached; missing id refetches once", async () => {
  const { c, calls } = stubbed(() => [person("p-a", "Alice")], [msg("p-a", ["p-a"])]);
  await c.chatEvolve("o", "");
  await c.chatEvolve("o", "");
  const rosterCalls = () => calls.filter((p) => p.includes("participants/")).length;
  assert.equal(rosterCalls(), 1);
  await c.resolveNames("o", ["p-new"]);
  assert.equal(rosterCalls(), 2);
});

test("roster failure never breaks reading messages", async () => {
  const { c } = stubbed(() => { throw new Error("boom"); }, [msg("p-a", ["p-a"])]);
  const { messages } = await c.chatEvolve("o", "");
  assert.equal(messages[0]!.text, "hi");
  assert.equal(messages[0]!.reactions[0]!.name, undefined);
});
