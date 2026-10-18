import { beforeEach, expect, it, vi } from "vitest";
import * as Effect from "effect/Effect";
import { Providers } from "alchemy/Cloudflare";
import { emailAccessGate } from "../deploy/alchemy/alchemy.access";

const access = vi.hoisted(() => ({
  Policy: vi.fn(),
  Application: vi.fn(),
}));

vi.mock("alchemy/Cloudflare", async (importOriginal) => {
  const { Providers } =
    await importOriginal<typeof import("alchemy/Cloudflare")>();
  return { Providers, Access: access };
});

beforeEach(() => {
  access.Policy.mockReturnValue(Effect.succeed({ policyId: "allowed-users" }));
  access.Application.mockReturnValue(Effect.succeed({ aud: "app-audience" }));
});

it("protects the custom and preview hostnames with one email allow policy", async () => {
  await Effect.runPromise(
    emailAccessGate({
      policyId: "SelfHostAllowUsers",
      applicationId: "SelfHostAccess",
      policyName: "OpenSEO users",
      applicationName: "OpenSEO",
      domain: "seo.example.com",
      additionalDomains: ["*-open-seo-selfhost.account.workers.dev"],
      emails: ["owner@example.com"],
    }).pipe(
      // Resource constructors are mocked, so this test needs no live providers.
      Effect.provideService(Providers, {
        kind: "ProviderCollection",
        get: () => undefined,
        providers: {},
      }),
    ),
  );

  expect(access.Policy).toHaveBeenCalledWith("SelfHostAllowUsers", {
    name: "OpenSEO users",
    decision: "allow",
    include: [{ email: { email: "owner@example.com" } }],
  });
  expect(access.Application).toHaveBeenCalledWith(
    "SelfHostAccess",
    expect.objectContaining({
      domain: "seo.example.com",
      destinations: [
        { type: "public", uri: "seo.example.com" },
        {
          type: "public",
          uri: "*-open-seo-selfhost.account.workers.dev",
        },
      ],
      policies: ["allowed-users"],
    }),
  );
});
