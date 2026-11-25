import fs from 'node:fs';
import path from 'node:path';
import { StorageManager } from './storage';

function isPresent(val: unknown): boolean {
  if (val === null || val === undefined) return false;
  if (typeof val === 'string') {
    const t = val.trim().toLowerCase();
    return Boolean(t) && t !== 'none' && t !== 'null' && t !== 'n/a' && t !== '0';
  }
  if (typeof val === 'number') {
    return Number.isFinite(val) && val > 0;
  }
  return true;
}

function safeAssetId(id: string): string {
  return String(id || '').replace(/[^a-zA-Z0-9_-]/g, '');
}

function getLocalBannerDirectories(): string[] {
  const dirs: string[] = [];
  const envDirs = [
    (process.env.BANNER_ASSETS_DIR || '').trim(),
    (process.env.FF_BANNER_ASSETS_DIR || '').trim()
  ].filter(Boolean);
  dirs.push(...envDirs);

  try {
    const dataDir = StorageManager.getMainStorage().getDataDir();
    dirs.push(path.join(dataDir, 'ff-assets', 'banners'));
    dirs.push(path.join(dataDir, 'banners'));
  } catch {
    dirs.push(path.join(process.cwd(), 'data', 'ff-assets', 'banners'));
    dirs.push(path.join(process.cwd(), 'data', 'banners'));
  }
  dirs.push(path.join(process.cwd(), 'banners'));

  return Array.from(new Set(dirs));
}

function getCacheFilePath(bannerId: string, ext: string = '.png'): string {
  try {
    return path.join(StorageManager.getMainStorage().getDataDir(), 'ff-assets', 'banners', `${bannerId}${ext}`);
  } catch {
    return path.join(process.cwd(), 'data', 'ff-assets', 'banners', `${bannerId}${ext}`);
  }
}

export interface ResolvedBannerAsset {
  buffer: Buffer;
  mimeType: string;
  fileName: string;
  bannerId: string;
  source: 'local' | 'remote';
}

export function extractEquippedBannerId(apiData: any): { bannerId: string; directUrl: string } {
  const p = apiData?.player && typeof apiData.player === 'object' && !apiData.player.error ? apiData.player : apiData;
  const raw = apiData?.raw && typeof apiData.raw === 'object' ? apiData.raw : {};

  let parsedRawData: any = null;
  const rawDataStr = apiData?.raw_data || p?.raw_data || raw?.raw_data;
  if (typeof rawDataStr === 'string' && rawDataStr.trim().startsWith('{')) {
    try {
      parsedRawData = JSON.parse(rawDataStr);
    } catch {}
  } else if (rawDataStr && typeof rawDataStr === 'object') {
    parsedRawData = rawDataStr;
  }

  const equipment = p?.equipment || apiData?.equipment || {};
  const equippedItems = parsedRawData?.EquippedItemsInfo || {};

  const rawBannerId =
    equipment?.banner_id ??
    p?.equipped_banner_id ??
    p?.banner_id ??
    raw?.equipped_banner_id ??
    raw?.banner_id ??
    equippedItems?.EquippedBannerId ??
    apiData?.banner_id;

  const bannerId = isPresent(rawBannerId) ? safeAssetId(String(rawBannerId).trim()) : '';

  const urlCandidate =
    apiData?.banner_url ||
    p?.banner_url ||
    raw?.banner_url ||
    (typeof raw?.banner_image === 'string' && /^https?:\/\//i.test(raw.banner_image) ? raw.banner_image : '') ||
    (typeof apiData?.banner_image === 'string' && /^https?:\/\//i.test(apiData.banner_image) ? apiData.banner_image : '');

  return {
    bannerId,
    directUrl: typeof urlCandidate === 'string' ? urlCandidate.trim() : ''
  };
}

function readLocalBannerFile(bannerId: string): ResolvedBannerAsset | null {
  const cleanId = safeAssetId(bannerId);
  if (!cleanId) return null;

  const exts: Array<{ ext: string; mimeType: string }> = [
    { ext: '.png', mimeType: 'image/png' },
    { ext: '.jpg', mimeType: 'image/jpeg' },
    { ext: '.jpeg', mimeType: 'image/jpeg' },
    { ext: '.webp', mimeType: 'image/webp' }
  ];

  for (const dir of getLocalBannerDirectories()) {
    for (const { ext, mimeType } of exts) {
      const filePath = path.join(dir, `${cleanId}${ext}`);
      try {
        if (!fs.existsSync(filePath)) continue;
        const stat = fs.statSync(filePath);
        if (!stat.isFile() || stat.size === 0 || stat.size > 10 * 1024 * 1024) continue;
        const buffer = fs.readFileSync(filePath);
        if (buffer.length > 0) {
          return {
            buffer,
            mimeType,
            fileName: `${cleanId}${ext}`,
            bannerId: cleanId,
            source: 'local'
          };
        }
      } catch {
        // Continue searching
      }
    }
  }

  return null;
}

async function fetchRemoteBannerImage(
  url: string,
  bannerId: string,
  timeoutMs = 5000
): Promise<ResolvedBannerAsset | null> {
  if (!url || !/^https?:\/\//i.test(url)) return null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        Accept: 'image/png,image/jpeg,image/webp,image/*,*/*',
        'User-Agent': 'Mozilla/5.0'
      }
    });
    clearTimeout(timer);
    if (!res.ok) return null;

    const rawCt = String(res.headers.get('content-type') || '').toLowerCase().split(';')[0].trim();
    if (!rawCt.startsWith('image/')) return null;

    const arr = await res.arrayBuffer();
    if (!arr || arr.byteLength === 0 || arr.byteLength > 10 * 1024 * 1024) return null;

    const buffer = Buffer.from(arr);
    const ext = rawCt === 'image/jpeg'
      ? '.jpg'
      : rawCt === 'image/webp'
        ? '.webp'
        : '.png';

    const cleanId = safeAssetId(bannerId) || 'banner';
    try {
      const cachePath = getCacheFilePath(cleanId, ext);
      fs.mkdirSync(path.dirname(cachePath), { recursive: true });
      fs.writeFileSync(cachePath, buffer);
    } catch {}

    return {
      buffer,
      mimeType: rawCt,
      fileName: `${cleanId}${ext}`,
      bannerId: cleanId,
      source: 'remote'
    };
  } catch {
    return null;
  }
}

export async function resolveExistingBannerAsset(apiData: any): Promise<{
  bannerId: string;
  asset: ResolvedBannerAsset | null;
}> {
  const { bannerId, directUrl } = extractEquippedBannerId(apiData);

  if (bannerId) {
    // 1. Check local VPS banner directories first
    const localAsset = readLocalBannerFile(bannerId);
    if (localAsset) {
      return { bannerId, asset: localAsset };
    }

    // 2. Check configured FF_BANNER_CDN_URL and public Free Fire banner asset sources
    const customCdn = (process.env.FF_BANNER_CDN_URL || '').trim();
    const urlTemplates = [
      customCdn,
      'https://raw.githubusercontent.com/90xExe/FreeFireAllIconBy90x/main/BANNERS/{id}.png',
      'https://cdn.jsdelivr.net/gh/90xExe/FreeFireAllIconBy90x@main/BANNERS/{id}.png'
    ].filter(Boolean);

    for (const tpl of urlTemplates) {
      const targetUrl = tpl.includes('{id}')
        ? tpl.replace(/\{id\}/g, encodeURIComponent(bannerId))
        : `${tpl.replace(/\/+$/, '')}/${encodeURIComponent(bannerId)}.png`;
      const fetched = await fetchRemoteBannerImage(targetUrl, bannerId);
      if (fetched) {
        return { bannerId, asset: fetched };
      }
    }
  }

  // 3. Direct full HTTP banner URL from API response (only if provided explicitly by upstream)
  if (directUrl) {
    const fetched = await fetchRemoteBannerImage(directUrl, bannerId || 'banner');
    if (fetched) {
      return { bannerId: bannerId || fetched.bannerId, asset: fetched };
    }
  }

  return { bannerId, asset: null };
}
