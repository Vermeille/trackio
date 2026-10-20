import { afterEach, describe, expect, test } from "vitest";
import {
  applyUrlTokens,
  clearWriteToken,
  getWriteToken,
  saveWriteToken,
  setWriteToken,
} from "./urlTokens.js";

function setBrowser(protocol = "https:") {
  let cookieValue = "";
  let lastCookie = "";
  const replacedUrls = [];

  globalThis.document = {
    get cookie() {
      return cookieValue;
    },
    set cookie(value) {
      lastCookie = value;
      cookieValue = value.includes("max-age=0") ? "" : value.split(";")[0];
    },
  };
  globalThis.window = {
    location: {
      protocol,
      pathname: "/registry",
      search: "?project=test&write_token=secret",
    },
    history: {
      replaceState(_state, _title, url) {
        replacedUrls.push(url);
      },
    },
  };
  return { getLastCookie: () => lastCookie, replacedUrls };
}

afterEach(() => {
  delete globalThis.document;
  delete globalThis.window;
});

describe("write token browser access", () => {
  test("persists an HTTPS token in a secure, seven-day cookie", () => {
    const browser = setBrowser();
    setWriteToken("secret");

    expect(browser.getLastCookie()).toContain("; Secure");
    expect(browser.getLastCookie()).toContain("max-age=604800");
    expect(browser.getLastCookie()).toContain("SameSite=Lax");
    expect(getWriteToken()).toBe("secret");
  });

  test("supports local HTTP without a Secure cookie", () => {
    const browser = setBrowser("http:");
    setWriteToken("secret");

    expect(browser.getLastCookie()).not.toContain("; Secure");
  });

  test("removes a stored token", () => {
    const browser = setBrowser();
    setWriteToken("secret");
    clearWriteToken();

    expect(browser.getLastCookie()).toContain("max-age=0");
    expect(getWriteToken()).toBeNull();
  });

  test("accepts a token from the URL and removes the query parameter", () => {
    const browser = setBrowser();
    applyUrlTokens();

    expect(getWriteToken()).toBe("secret");
    expect(browser.replacedUrls).toEqual(["/registry?project=test"]);
  });

  test("keeps a token only after self-hosted write access is verified", async () => {
    setBrowser();

    expect(
      await saveWriteToken("valid", async () => ({ spaces: false, allowed: true })),
    ).toBe(true);
    expect(getWriteToken()).toBe("valid");
  });

  test("restores the old token if the replacement is rejected", async () => {
    setBrowser();
    setWriteToken("previous");

    expect(
      await saveWriteToken("invalid", async () => ({ spaces: false, allowed: false })),
    ).toBe(false);
    expect(getWriteToken()).toBe("previous");
  });

  test("clears a rejected token when there was no previous one", async () => {
    setBrowser();

    expect(
      await saveWriteToken("invalid", async () => ({ spaces: false, allowed: false })),
    ).toBe(false);
    expect(getWriteToken()).toBeNull();
  });

  test("restores the previous token if verification fails", async () => {
    setBrowser();
    setWriteToken("previous");

    await expect(
      saveWriteToken("replacement", async () => {
        throw new Error("connection failed");
      }),
    ).rejects.toThrow("connection failed");
    expect(getWriteToken()).toBe("previous");
  });

  test("does not treat Space write access as local token verification", async () => {
    setBrowser();

    expect(
      await saveWriteToken("invalid", async () => ({ spaces: true, allowed: true })),
    ).toBe(false);
    expect(getWriteToken()).toBeNull();
  });
});
