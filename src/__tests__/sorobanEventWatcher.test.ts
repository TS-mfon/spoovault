// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { sorobanEventWatcher } from "../services/sorobanEventWatcher.service";

describe("SorobanEventWatcher", () => {
  const rpcUrl = "https://mock.soroban.rpc";
  const contractId = "C123456789";

  beforeEach(() => {
    vi.useFakeTimers();
    const mockFetch = vi.fn();
    globalThis.fetch = mockFetch;
    global.fetch = mockFetch;
    if (typeof window !== "undefined") {
      (window as any).fetch = mockFetch;
      vi.spyOn(window, "dispatchEvent").mockImplementation(() => true);
    }
  });

  afterEach(() => {
    sorobanEventWatcher.stop();
    vi.restoreAllMocks();
    vi.useRealTimers();
    // Reset private state via fresh instance if needed, but since it's a singleton, 
    // stopping it and clearing listeners is usually enough for tests.
    // Clean up generic listeners:
    // @ts-ignore
    sorobanEventWatcher.listeners = {};
    // @ts-ignore
    sorobanEventWatcher.lastCursor = undefined;
  });

  it("should not fetch events if not started", async () => {
    // @ts-ignore
    await sorobanEventWatcher.poll();
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("should initialize and fetch latest ledger on first poll", async () => {
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sequence: 1000 }
        })
      })
      .mockResolvedValue({
        ok: true,
        json: async () => ({
          result: { events: [] }
        })
      });

    sorobanEventWatcher.start(rpcUrl, contractId);
    
    // Allow initial poll microtasks to complete
    await vi.advanceTimersByTimeAsync(0);

    expect(global.fetch).toHaveBeenCalled();
    const fetchCall1 = (global.fetch as any).mock.calls[0];
    expect(fetchCall1[0]).toBe(rpcUrl);
    expect(JSON.parse(fetchCall1[1].body).method).toBe("getLatestLedger");

    const fetchCall2 = (global.fetch as any).mock.calls[1];
    expect(JSON.parse(fetchCall2[1].body).method).toBe("getEvents");
  });

  it("should fetch events and dispatch to listeners when events are present", async () => {
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: {
            events: [
              {
                type: "contract",
                pagingToken: "1001-1",
                topic: ["VaultCreated_XDR"],
                value: { some: "data" }
              }
            ]
          }
        })
      });

    const mockCallback = vi.fn();
    sorobanEventWatcher.on("SorobanEvent", mockCallback);

    sorobanEventWatcher.start(rpcUrl, contractId);
    await vi.advanceTimersByTimeAsync(5000);

    expect(mockCallback).toHaveBeenCalled();

    sorobanEventWatcher.off("SorobanEvent", mockCallback);
  });

  it("should handle RPC errors gracefully", async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      statusText: "Internal Server Error"
    });

    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    sorobanEventWatcher.start(rpcUrl, contractId);
    // getLatestLedger fails and returns 0.
    await vi.runOnlyPendingTimersAsync();

    expect(consoleSpy).not.toHaveBeenCalled(); // getLatestLedger swallows error and returns 0

    // advance to next poll (which won't happen because startLedger === 0 returns early)
    await vi.advanceTimersByTimeAsync(5000);
    
    // Now simulate getLatestLedger succeeding, but getEvents failing
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } })
      })
      .mockResolvedValueOnce({
        ok: false,
        statusText: "Bad Gateway"
      });

    // @ts-ignore
    sorobanEventWatcher.lastCursor = undefined;
    
    // trigger a poll to test the error block inside fetchEvents
    // @ts-ignore
    await sorobanEventWatcher.poll();

    expect(consoleSpy).toHaveBeenCalledWith(
      "SorobanEventWatcher polling error:",
      expect.any(Error)
    );

    consoleSpy.mockRestore();
  });
});
