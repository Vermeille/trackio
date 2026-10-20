const WRITE_TOKEN_COOKIE = "trackio_write_token";
const WRITE_TOKEN_MAX_AGE = 60 * 60 * 24 * 7;

function writeTokenCookie(token, maxAge) {
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${WRITE_TOKEN_COOKIE}=${encodeURIComponent(token)}; path=/; max-age=${maxAge}; SameSite=Lax${secure}`;
}

export function getWriteToken() {
  const prefix = `${WRITE_TOKEN_COOKIE}=`;
  const cookie = document.cookie.split(";").map((entry) => entry.trim()).find((entry) => entry.startsWith(prefix));
  if (!cookie) return null;
  try {
    return decodeURIComponent(cookie.slice(prefix.length));
  } catch {
    return null;
  }
}

export function setWriteToken(token) {
  writeTokenCookie(token, WRITE_TOKEN_MAX_AGE);
}

export function clearWriteToken() {
  writeTokenCookie("", 0);
}

export async function saveWriteToken(token, verifyAccess) {
  const previousToken = getWriteToken();
  setWriteToken(token);
  try {
    const status = await verifyAccess();
    if (status?.allowed && !status.spaces) return true;
    if (previousToken != null) setWriteToken(previousToken);
    else clearWriteToken();
    return false;
  } catch (error) {
    if (previousToken != null) setWriteToken(previousToken);
    else clearWriteToken();
    throw error;
  }
}

export function applyUrlTokens() {
  const params = new URLSearchParams(window.location.search);
  let changed = false;
  const writeToken = params.get("write_token");
  if (writeToken) {
    setWriteToken(writeToken);
    params.delete("write_token");
    changed = true;
  }
  const oauthSession = params.get("oauth_session");
  if (oauthSession) {
    sessionStorage.setItem("trackio_oauth_session", oauthSession);
    params.delete("oauth_session");
    changed = true;
  }
  if (changed) {
    const query = params.toString();
    const path = window.location.pathname + (query ? `?${query}` : "");
    window.history.replaceState({}, "", path);
  }
}
