import { afterEach, describe, expect, it, vi } from "vitest";
import { createPonytailRules } from "./ponytail.js";

const BASE = "http://ponytail.test:8787";

describe("ponytail rules", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is a no-op without a URL or when off", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await createPonytailRules({ url: "" })()).toBe("");
    expect(await createPonytailRules({ url: BASE, mode: "off" })()).toBe("");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fetches once, caches, and revalidates with the ETag", async () => {
    let clock = 0;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("RULES v1", { headers: { ETag: '"a"' } }))
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    vi.stubGlobal("fetch", fetchMock);
    const get = createPonytailRules({ url: `${BASE}/`, mode: "FULL", now: () => clock });

    expect(await get()).toBe("RULES v1");
    expect(await get()).toBe("RULES v1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1/rules?mode=full`);

    clock = 11 * 60_000;
    expect(await get()).toBe("RULES v1");
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(fetchMock.mock.calls[1][1].headers).toEqual({ "If-None-Match": '"a"' });
  });

  it("returns empty when the service is down and backs off before retrying", async () => {
    let clock = 0;
    const fetchMock = vi.fn(async (_url: string) => new Response("nope", { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);
    const warn = vi.fn();
    const get = createPonytailRules({ url: BASE, now: () => clock, warn });

    expect(await get()).toBe("");
    expect(await get()).toBe("");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1/rules?mode=compact`);
    expect(warn).toHaveBeenCalledWith("Ponytail rules unavailable", { url: BASE, err: "Error: HTTP 503" });

    clock = 61_000;
    await get();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
