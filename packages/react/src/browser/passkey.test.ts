import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@simplewebauthn/browser", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@simplewebauthn/browser")>()),
  startRegistration: vi.fn(),
  startAuthentication: vi.fn(),
}));

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { VaultServiceClient } from "../client.js";
import { PasskeyUnsupportedError, registerPasskey } from "./passkey.js";

const PRF_OUTPUT = new Uint8Array([1, 2, 3]).buffer;

function fakeClient() {
  const request = vi.fn(async (path: string, _init?: RequestInit): Promise<unknown> => {
    if (path === "/vault/methods/passkey/register-options") {
      return { options: { rp: { id: "localhost", name: "Test" }, challenge: "c" }, prfSalt: "c2FsdA" };
    }
    return { status: "registered" };
  });
  return { client: { baseUrl: "", request } as unknown as VaultServiceClient, request };
}

function registration(prf: unknown) {
  return { id: "cred-1", clientExtensionResults: { prf } } as never;
}

describe("registerPasskey", () => {
  beforeEach(() => vi.mocked(startAuthentication).mockReset());

  it("uses the PRF output returned at creation", async () => {
    vi.mocked(startRegistration).mockResolvedValueOnce(registration({ enabled: true, results: { first: PRF_OUTPUT } }));
    const { client, request } = fakeClient();

    await registerPasskey(client, "device");

    expect(startAuthentication).not.toHaveBeenCalled();
    expect(JSON.parse(request.mock.calls[1]![1]!.body as string).prfOutput).toBe("AQID");
  });

  it("reads the output with one assertion when creation only says enabled", async () => {
    vi.mocked(startRegistration).mockResolvedValueOnce(registration({ enabled: true }));
    vi.mocked(startAuthentication).mockResolvedValueOnce({
      clientExtensionResults: { prf: { results: { first: PRF_OUTPUT } } },
    } as never);
    const { client, request } = fakeClient();

    await registerPasskey(client, "device");

    const options = vi.mocked(startAuthentication).mock.calls[0]![0].optionsJSON;
    expect(options.rpId).toBe("localhost");
    expect(options.allowCredentials).toEqual([{ id: "cred-1", type: "public-key" }]);
    expect(JSON.parse(request.mock.calls[1]![1]!.body as string).prfOutput).toBe("AQID");
  });

  it("gives up without registering when PRF isn't supported", async () => {
    vi.mocked(startRegistration).mockResolvedValueOnce(registration(undefined));
    const { client, request } = fakeClient();

    const error = await registerPasskey(client, "device").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PasskeyUnsupportedError);
    expect((error as PasskeyUnsupportedError).reason).toBe("no-prf");
    expect(startAuthentication).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("reports a claimed-but-missing output as no-prf-output", async () => {
    vi.mocked(startRegistration).mockResolvedValueOnce(registration({ enabled: true }));
    vi.mocked(startAuthentication).mockResolvedValueOnce({ clientExtensionResults: {} } as never);
    const { client, request } = fakeClient();

    const error = await registerPasskey(client, "device").catch((e: unknown) => e);

    expect((error as PasskeyUnsupportedError).reason).toBe("no-prf-output");
    expect(request).toHaveBeenCalledTimes(1);
  });
});
