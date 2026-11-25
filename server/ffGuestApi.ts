import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { StorageManager } from './storage';

export interface GuestSessionRecord {
  token: string;
  openId?: string;
  guestUid?: string;
  expiresAt: number;
  obtainedAt: number;
  source: 'env_token' | 'guest_login';
  credentialFingerprint: string;
}

export type GuestBancheckResult =
  | {
      ok: true;
      uid: string;
      username: string;
      nickname: string;
      region: string;
      level: string;
      likes: string;
      is_banned: boolean;
      status: 'Banned' | 'Not Banned';
      ban_type?: string;
      ban_time?: string;
      ban_reason?: string;
      source: 'guest_api';
    }
  | {
      ok: false;
      code:
        | 'INVALID_UID'
        | 'GUEST_CREDENTIALS_MISSING'
        | 'INVALID_GUEST_CREDENTIALS'
        | 'PLAYER_NOT_FOUND'
        | 'UPSTREAM_ERROR';
      error: string;
    };

function isPresent(val: unknown): boolean {
  if (val === null || val === undefined) return false;
  if (typeof val === 'string') {
    const s = val.trim().toLowerCase();
    return Boolean(s) && s !== 'none' && s !== 'null' && s !== 'n/a';
  }
  return true;
}

function parseBanBoolean(val: unknown): boolean | null {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'number') {
    if (val === 1) return true;
    if (val === 0) return false;
    return null;
  }
  if (typeof val === 'string') {
    const s = val.trim().toLowerCase();
    if (!s) return null;
    if (/\b(not[\s_-]?banned|unbanned|clean|safe|no)\b/i.test(s) || s === '0' || s === 'false') {
      return false;
    }
    if (/\b(banned|suspended|yes)\b/i.test(s) || s === '1' || s === 'true') {
      return true;
    }
  }
  return null;
}

function extractBanMeta(
  json: any,
  container: any,
  pObj: any,
  isBanned: boolean | null
): { banType?: string; banTime?: string; banReason?: string } {
  if (isBanned !== true) return {};

  const rawBanType =
    json?.ban_type ??
    json?.banType ??
    container?.ban_type ??
    container?.banType ??
    pObj?.ban_type ??
    pObj?.banType;

  const rawBanTime =
    json?.ban_time ??
    json?.banTime ??
    json?.ban_duration ??
    json?.banDuration ??
    json?.remaining_time ??
    json?.remainingTime ??
    json?.ban_until ??
    json?.banUntil ??
    json?.expires_at ??
    json?.expire_at ??
    container?.ban_time ??
    container?.banTime ??
    container?.ban_duration ??
    container?.banDuration ??
    container?.remaining_time ??
    container?.ban_until ??
    container?.expires_at ??
    pObj?.ban_time ??
    pObj?.ban_duration ??
    pObj?.ban_until;

  const rawMsg =
    typeof json?.msg === 'string' &&
    json.msg.trim() &&
    !/^(T_P_WRONG_ACCOUNT|success|ok)$/i.test(json.msg.trim())
      ? json.msg
      : undefined;

  const rawBanReason =
    json?.ban_reason ??
    json?.banReason ??
    json?.reason ??
    container?.ban_reason ??
    container?.banReason ??
    container?.reason ??
    pObj?.ban_reason ??
    pObj?.banReason ??
    pObj?.reason ??
    rawMsg;

  let banType = 'Permanent';
  if (isPresent(rawBanType)) {
    const s = String(rawBanType).trim();
    banType = /temp/i.test(s) ? 'Temporary' : /perm/i.test(s) ? 'Permanent' : s;
  } else if (isPresent(rawBanTime) && !/^(perm|permanent|forever|lifetime|0)$/i.test(String(rawBanTime).trim())) {
    banType = 'Temporary';
  }

  let banTime = banType === 'Permanent' ? 'Permanent' : 'Unknown';
  if (banType !== 'Permanent' && isPresent(rawBanTime)) {
    const s = String(rawBanTime).trim();
    if (/^\d{10}$/.test(s)) {
      banTime = new Date(Number(s) * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    } else if (/^\d{13}$/.test(s)) {
      banTime = new Date(Number(s)).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    } else {
      banTime = s;
    }
  }

  const banReason = isPresent(rawBanReason)
    ? String(rawBanReason).trim()
    : 'Not provided';

  return { banType, banTime, banReason };
}

function decodeJwtExpMs(token: string): number | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
    const payload = JSON.parse(payloadJson);
    if (typeof payload?.exp === 'number' && Number.isFinite(payload.exp) && payload.exp > 0) {
      return payload.exp * 1000;
    }
  } catch {}
  return null;
}

export class FreeFireGuestService {
  private static cachedSession: GuestSessionRecord | null = null;
  private static refreshInFlight: Promise<{ ok: true; session: GuestSessionRecord } | { ok: false; code: 'GUEST_CREDENTIALS_MISSING' | 'INVALID_GUEST_CREDENTIALS'; error: string }> | null = null;
  private static playerCache: Map<string, { data: any; fetchedAt: number }> = new Map();

  private static getEnvCredentials(): {
    guestUid: string;
    guestPassword: string;
    guestToken: string;
    guestOpenId: string;
    loginUrl: string;
    playerUrl: string;
    bancheckUpstreamUrl: string;
    fingerprint: string;
  } {
    const guestUid = (process.env.FF_GUEST_UID || '').trim();
    const guestPassword = (process.env.FF_GUEST_PASSWORD || '').trim();
    const guestToken = (process.env.FF_GUEST_TOKEN || '').trim();
    const guestOpenId = (process.env.FF_GUEST_OPEN_ID || '').trim();
    const loginUrl = (process.env.FF_GUEST_LOGIN_URL || 'https://100067.connect.garena.com/oauth/guest/token/grant').trim();
    const playerUrl = (process.env.FF_GUEST_PLAYER_URL || '').trim();
    const bancheckUpstreamUrl = (process.env.FF_BANCHECK_UPSTREAM_URL || '').trim();

    const fingerprint = crypto
      .createHash('sha256')
      .update(`${guestUid}|${guestPassword}|${guestToken}|${guestOpenId}|${loginUrl}`)
      .digest('hex')
      .slice(0, 24);

    return {
      guestUid,
      guestPassword,
      guestToken,
      guestOpenId,
      loginUrl,
      playerUrl,
      bancheckUpstreamUrl,
      fingerprint
    };
  }

  private static getSessionCacheFilePath(): string {
    const dataDir = StorageManager.getMainStorage().getDataDir();
    return path.join(dataDir, 'ff_guest_session.json');
  }

  private static loadDiskSession(expectedFingerprint: string): GuestSessionRecord | null {
    try {
      const filePath = this.getSessionCacheFilePath();
      if (!fs.existsSync(filePath)) return null;
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw) as GuestSessionRecord;
      if (
        !parsed ||
        typeof parsed.token !== 'string' ||
        !parsed.token ||
        parsed.credentialFingerprint !== expectedFingerprint
      ) {
        return null;
      }
      if (typeof parsed.expiresAt !== 'number' || Date.now() >= parsed.expiresAt - 60_000) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  private static saveDiskSession(session: GuestSessionRecord): void {
    try {
      const filePath = this.getSessionCacheFilePath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      const tmpPath = `${filePath}.tmp`;
      fs.writeFileSync(tmpPath, JSON.stringify(session, null, 2), { encoding: 'utf8', mode: 0o600 });
      fs.renameSync(tmpPath, filePath);
    } catch (err: any) {
      console.warn('[FFGuestAPI] Failed to persist guest session cache:', err?.message || err);
    }
  }

  private static clearCachedSession(): void {
    this.cachedSession = null;
    try {
      const filePath = this.getSessionCacheFilePath();
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch {}
  }

  public static getStatus(): {
    configured: boolean;
    hasGuestUid: boolean;
    hasGuestPassword: boolean;
    hasGuestToken: boolean;
    sessionCached: boolean;
    expiresAt: number | null;
  } {
    const creds = this.getEnvCredentials();
    const hasLoginPair = Boolean(creds.guestUid && creds.guestPassword);
    const hasToken = Boolean(creds.guestToken);
    const active =
      (this.cachedSession &&
        this.cachedSession.credentialFingerprint === creds.fingerprint &&
        Date.now() < this.cachedSession.expiresAt - 60_000
        ? this.cachedSession
        : null) || this.loadDiskSession(creds.fingerprint);

    return {
      configured: hasLoginPair || hasToken,
      hasGuestUid: Boolean(creds.guestUid),
      hasGuestPassword: Boolean(creds.guestPassword),
      hasGuestToken: hasToken,
      sessionCached: Boolean(active),
      expiresAt: active ? active.expiresAt : null
    };
  }

  public static async ensureGuestSession(
    forceRefresh: boolean = false
  ): Promise<
    | { ok: true; session: GuestSessionRecord }
    | { ok: false; code: 'GUEST_CREDENTIALS_MISSING' | 'INVALID_GUEST_CREDENTIALS'; error: string }
  > {
    const creds = this.getEnvCredentials();
    const hasLoginPair = Boolean(creds.guestUid && creds.guestPassword);
    const hasDirectToken = Boolean(creds.guestToken);

    if (!hasLoginPair && !hasDirectToken) {
      return {
        ok: false,
        code: 'GUEST_CREDENTIALS_MISSING',
        error: 'Free Fire Guest credentials are not configured. Set FF_GUEST_UID and FF_GUEST_PASSWORD (or FF_GUEST_TOKEN) in .env.'
      };
    }

    if (!forceRefresh) {
      if (
        this.cachedSession &&
        this.cachedSession.credentialFingerprint === creds.fingerprint &&
        Date.now() < this.cachedSession.expiresAt - 60_000
      ) {
        return { ok: true, session: this.cachedSession };
      }

      const fromDisk = this.loadDiskSession(creds.fingerprint);
      if (fromDisk) {
        this.cachedSession = fromDisk;
        return { ok: true, session: fromDisk };
      }
    } else {
      this.clearCachedSession();
    }

    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }

    this.refreshInFlight = (async () => {
      try {
        // Prefer credential grant login when FF_GUEST_UID & FF_GUEST_PASSWORD are set and refreshing or no static token
        if (hasLoginPair && (forceRefresh || !hasDirectToken)) {
          const authResult = await this.authenticateGuestAccount(creds);
          if (authResult.ok) {
            this.cachedSession = authResult.session;
            this.saveDiskSession(authResult.session);
            return authResult;
          }
          // Fall back to static FF_GUEST_TOKEN only if not forced refresh and static token is set
          if (!hasDirectToken || forceRefresh) {
            return authResult;
          }
        }

        if (hasDirectToken) {
          const jwtExp = decodeJwtExpMs(creds.guestToken);
          const now = Date.now();
          const session: GuestSessionRecord = {
            token: creds.guestToken,
            openId: creds.guestOpenId || undefined,
            guestUid: creds.guestUid || undefined,
            obtainedAt: now,
            expiresAt: jwtExp && jwtExp > now ? jwtExp : now + 6 * 3600 * 1000,
            source: 'env_token',
            credentialFingerprint: creds.fingerprint
          };
          this.cachedSession = session;
          this.saveDiskSession(session);
          return { ok: true as const, session };
        }

        return {
          ok: false as const,
          code: 'GUEST_CREDENTIALS_MISSING' as const,
          error: 'Free Fire Guest credentials are incomplete. Provide FF_GUEST_UID and FF_GUEST_PASSWORD, or FF_GUEST_TOKEN.'
        };
      } finally {
        this.refreshInFlight = null;
      }
    })();

    return this.refreshInFlight;
  }

  private static async authenticateGuestAccount(creds: {
    guestUid: string;
    guestPassword: string;
    guestOpenId: string;
    loginUrl: string;
    fingerprint: string;
  }): Promise<
    | { ok: true; session: GuestSessionRecord }
    | { ok: false; code: 'INVALID_GUEST_CREDENTIALS'; error: string }
  > {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 14000);

      const formParams = new URLSearchParams({
        uid: creds.guestUid,
        password: creds.guestPassword,
        response_type: 'token',
        client_id: '100067',
        client_type: '2',
        redirect_uri: 'https://api.ff.garena.co.id/auth/auth/callback_n?site=https://api-ticket.ff.garena.co.id'
      });

      const res = await fetch(creds.loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'User-Agent': 'GarenaMSDK/4.0.19P8(Redmi Note 8 ;Android 11;en;US;)'
        },
        body: formParams.toString(),
        signal: controller.signal
      });
      clearTimeout(timer);

      const json: any = await res.json().catch(() => null);
      const token =
        json?.access_token ||
        json?.token ||
        json?.jwt ||
        json?.data?.access_token ||
        json?.data?.token;

      if (!res.ok || !token || typeof token !== 'string') {
        const errCode = String(json?.error || json?.msg || '').trim();
        return {
          ok: false,
          code: 'INVALID_GUEST_CREDENTIALS',
          error: errCode
            ? `Free Fire Guest login rejected (${errCode}). Verify FF_GUEST_UID and FF_GUEST_PASSWORD.`
            : 'Free Fire Guest login failed. Verify FF_GUEST_UID and FF_GUEST_PASSWORD in .env.'
        };
      }

      const now = Date.now();
      const expiresInSec = Number(json?.expires_in || json?.data?.expires_in || 0);
      const jwtExp = decodeJwtExpMs(token);
      const expiresAt =
        jwtExp && jwtExp > now
          ? jwtExp
          : now + (Number.isFinite(expiresInSec) && expiresInSec > 60 ? expiresInSec * 1000 : 6 * 3600 * 1000);

      const session: GuestSessionRecord = {
        token,
        openId: String(json?.open_id || json?.data?.open_id || creds.guestOpenId || '').trim() || undefined,
        guestUid: creds.guestUid,
        obtainedAt: now,
        expiresAt,
        source: 'guest_login',
        credentialFingerprint: creds.fingerprint
      };

      return { ok: true, session };
    } catch (err: any) {
      return {
        ok: false,
        code: 'INVALID_GUEST_CREDENTIALS',
        error: `Free Fire Guest authentication request failed: ${err?.message || 'network error'}`
      };
    }
  }

  private static async fetchPlayerProfile(
    uid: string,
    session: GuestSessionRecord,
    customPlayerUrl: string
  ): Promise<any | null> {
    const cached = this.playerCache.get(uid);
    if (cached && Date.now() - cached.fetchedAt < 5 * 60 * 1000) {
      return cached.data;
    }

    const urlsToTry: Array<{ url: string; headers: Record<string, string> }> = [];
    if (customPlayerUrl) {
      const targetUrl = customPlayerUrl.includes('{uid}')
        ? customPlayerUrl.replace(/\{uid\}/g, encodeURIComponent(uid))
        : `${customPlayerUrl}${customPlayerUrl.includes('?') ? '&' : '?'}uid=${encodeURIComponent(uid)}`;
      urlsToTry.push({
        url: targetUrl,
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${session.token}`,
          ...(session.openId ? { 'X-Open-Id': session.openId } : {}),
          ...(session.guestUid ? { 'X-Guest-Uid': session.guestUid } : {})
        }
      });
    }

    urlsToTry.push({
      url: `https://auraffxserverinfocheckerapi.onrender.com/api/player?uid=${encodeURIComponent(uid)}`,
      headers: { Accept: 'application/json' }
    });

    for (const candidate of urlsToTry) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 14000);
        const res = await fetch(candidate.url, {
          method: 'GET',
          headers: candidate.headers,
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) continue;

        const json: any = await res.json().catch(() => null);
        if (!json || json.success === false || json.error) continue;

        const playerObj = json.player && typeof json.player === 'object' && !json.player.error ? json.player : json;
        if (
          isPresent(playerObj?.name) ||
          isPresent(playerObj?.nickname) ||
          isPresent(playerObj?.username) ||
          isPresent(json?.name) ||
          isPresent(playerObj?.uid) ||
          isPresent(json?.uid)
        ) {
          if (this.playerCache.size > 200) {
            const oldest = this.playerCache.keys().next().value;
            if (oldest) this.playerCache.delete(oldest);
          }
          this.playerCache.set(uid, { data: json, fetchedAt: Date.now() });
          return json;
        }
      } catch {}
    }

    return null;
  }

  private static async queryUpstreamBancheck(
    uid: string,
    session: GuestSessionRecord,
    upstreamOverrideUrl: string
  ): Promise<{
    unauthorized?: boolean;
    notFound?: boolean;
    isBanned: boolean | null;
    banType?: string;
    banTime?: string;
    banReason?: string;
    playerOverride?: {
      name?: string;
      region?: string;
      level?: string;
      likes?: string;
    };
  }> {
    const targetUrl = upstreamOverrideUrl
      ? (upstreamOverrideUrl.includes('{uid}')
          ? upstreamOverrideUrl.replace(/\{uid\}/g, encodeURIComponent(uid))
          : `${upstreamOverrideUrl}${upstreamOverrideUrl.includes('?') ? '&' : '?'}uid=${encodeURIComponent(uid)}`)
      : `https://ff.garena.com/api/antihack/check_banned?lang=en&uid=${encodeURIComponent(uid)}`;

    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': 'Mozilla/5.0',
      Authorization: `Bearer ${session.token}`,
      ...(session.openId ? { 'X-Open-Id': session.openId } : {}),
      ...(session.guestUid ? { 'X-Guest-Uid': session.guestUid } : {})
    };

    if (!upstreamOverrideUrl) {
      headers.Referer = 'https://ff.garena.com/en/support/';
      headers['x-requested-with'] = 'B6FksShzIgjfrYImLpTsadjS86sddhFH';
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      const res = await fetch(targetUrl, { method: 'GET', headers, signal: controller.signal });
      clearTimeout(timer);

      if (res.status === 401 || res.status === 403) {
        return { unauthorized: true, isBanned: null };
      }
      if (!res.ok) {
        return { isBanned: null };
      }

      const json: any = await res.json().catch(() => null);
      if (!json) return { isBanned: null };

      if (json?.msg === 'T_P_WRONG_ACCOUNT') {
        return { notFound: true, isBanned: null };
      }

      const container = json?.data && typeof json.data === 'object' ? json.data : json;
      const rawStatus =
        json?.is_banned ??
        json?.isBanned ??
        json?.banned ??
        container?.is_banned ??
        container?.isBanned ??
        container?.banned ??
        (json?.status !== 'success' && json?.status !== 'error' ? json?.status : undefined);

      const isBanned = parseBanBoolean(rawStatus);
      const pObj = json?.player && typeof json.player === 'object' ? json.player : container;
      const banMeta = extractBanMeta(json, container, pObj, isBanned);
      const playerOverride = {
        name: isPresent(pObj?.username || pObj?.nickname || pObj?.name)
          ? String(pObj.username || pObj.nickname || pObj.name).trim()
          : undefined,
        region: isPresent(pObj?.region_name || pObj?.region)
          ? String(pObj.region_name || pObj.region).trim()
          : undefined,
        level: isPresent(pObj?.level) ? String(pObj.level).trim() : undefined,
        likes: isPresent(pObj?.likes) ? String(pObj.likes).trim() : undefined
      };

      return {
        isBanned,
        banType: banMeta.banType,
        banTime: banMeta.banTime,
        banReason: banMeta.banReason,
        playerOverride
      };
    } catch {
      return { isBanned: null };
    }
  }

  public static async checkBanStatus(rawUid: string): Promise<GuestBancheckResult> {
    const cleanUid = String(rawUid || '').trim();
    if (!/^\d{5,20}$/.test(cleanUid)) {
      return {
        ok: false,
        code: 'INVALID_UID',
        error: 'Please provide a valid numeric Free Fire UID.'
      };
    }

    const sessionRes = await this.ensureGuestSession(false);
    if (!sessionRes.ok) {
      return sessionRes;
    }

    const creds = this.getEnvCredentials();
    let activeSession = sessionRes.session;

    const playerPromise = this.fetchPlayerProfile(cleanUid, activeSession, creds.playerUrl).catch(() => null);
    let banRes = await this.queryUpstreamBancheck(cleanUid, activeSession, creds.bancheckUpstreamUrl);

    // Auto-refresh expired/rejected session once if login credentials are available
    if (banRes.unauthorized && creds.guestUid && creds.guestPassword) {
      const refreshed = await this.ensureGuestSession(true);
      if (!refreshed.ok) {
        return refreshed;
      }
      activeSession = refreshed.session;
      banRes = await this.queryUpstreamBancheck(cleanUid, activeSession, creds.bancheckUpstreamUrl);
    }

    if (banRes.unauthorized) {
      return {
        ok: false,
        code: 'INVALID_GUEST_CREDENTIALS',
        error: 'Free Fire Guest session token was rejected. Update FF_GUEST_TOKEN or FF_GUEST_UID / FF_GUEST_PASSWORD in .env.'
      };
    }

    const playerData = await playerPromise;
    if (banRes.notFound || (banRes.isBanned === null && !playerData)) {
      return {
        ok: false,
        code: 'PLAYER_NOT_FOUND',
        error: `No Free Fire account found for UID ${cleanUid}.`
      };
    }

    if (banRes.isBanned === null) {
      return {
        ok: false,
        code: 'UPSTREAM_ERROR',
        error: 'Bancheck upstream service did not return a ban status. Please try again.'
      };
    }

    const p =
      playerData?.player && typeof playerData.player === 'object' && !playerData.player.error
        ? playerData.player
        : playerData;

    const username =
      banRes.playerOverride?.name ||
      (isPresent(p?.name)
        ? String(p.name).trim()
        : isPresent(playerData?.name)
          ? String(playerData.name).trim()
          : 'Unknown');

    let region = banRes.playerOverride?.region || '';
    if (!region) {
      const regionFlag = isPresent(p?.region_flag || playerData?.region_flag)
        ? String(p?.region_flag || playerData?.region_flag).trim()
        : '';
      const regionName = isPresent(p?.region_name || playerData?.region_name)
        ? String(p?.region_name || playerData?.region_name).trim()
        : '';
      const regionCode = isPresent(p?.region || playerData?.region)
        ? String(p?.region || playerData?.region).trim()
        : '';
      const regionText =
        regionName && regionCode && regionName.toLowerCase() !== regionCode.toLowerCase()
          ? `${regionName} (${regionCode})`
          : regionName || regionCode || 'Unknown';
      region = regionFlag ? `${regionFlag} ${regionText}` : regionText;
    }

    const level =
      banRes.playerOverride?.level ||
      (isPresent(p?.level ?? playerData?.level) ? String(p?.level ?? playerData?.level) : 'Unknown');
    const likes =
      banRes.playerOverride?.likes ||
      (isPresent(p?.likes ?? playerData?.likes) ? String(p?.likes ?? playerData?.likes) : '0');

    return {
      ok: true,
      uid: cleanUid,
      username,
      nickname: username,
      region,
      level,
      likes,
      is_banned: banRes.isBanned,
      status: banRes.isBanned ? 'Banned' : 'Not Banned',
      ...(banRes.isBanned
        ? {
            ban_type: banRes.banType || 'Permanent',
            ban_time: (banRes.banType || 'Permanent') === 'Permanent' ? 'Permanent' : (banRes.banTime || 'Unknown'),
            ban_reason: banRes.banReason || 'Not provided'
          }
        : {}),
      source: 'guest_api'
    };
  }
}
