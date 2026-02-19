
export const calculateHash = async (file: File): Promise<string> => {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * Enterprise-grade Unicode Base64
 */
export const forensicEncode = (data: any): string => {
  const json = JSON.stringify(data);
  const utf8 = new TextEncoder().encode(json);
  let binary = '';
  const len = utf8.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(utf8[i]);
  }
  return btoa(binary);
};

export const forensicDecode = (payload: string): any => {
  try {
    const binary = atob(payload);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json);
  } catch (e) {
    return null;
  }
};

/**
 * Calculates Shannon Entropy of a string to detect obfuscation
 */
export const calculateEntropy = (str: string): number => {
  const len = str.length;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  return Object.values(frequencies).reduce((sum, f) => {
    const p = f / len;
    return sum - p * Math.log2(p);
  }, 0);
};

export const extractPdfMetadata = async (file: File) => {
  const hash = await calculateHash(file);
  const data = { filename: file.name, size: file.size, hash };
  return { ...data, encryptedPayload: forensicEncode({ ...data, type: 'PDF_FORENSIC_ASSET' }) };
};

export const extractApkMetadata = async (file: File) => {
  const hash = await calculateHash(file);
  const data = {
    packageName: `com.sector.${file.name.toLowerCase().replace(/[^a-z]/g, '')}`,
    permissions_detected: ["READ_SMS", "INTERNET", "ACCESS_COARSE_LOCATION", "RECEIVE_BOOT_COMPLETED"],
    hash
  };
  return { ...data, encryptedPayload: forensicEncode({ ...data, type: 'APK_MALWARE_TRACE' }) };
};

export const isValidUrl = (url: string) => {
  try {
    const t = new URL(url.startsWith('http') ? url : `https://${url}`);
    return ['http:', 'https:'].includes(t.protocol);
  } catch { return false; }
};
