
export const calculateHash = async (file: File): Promise<string> => {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

export const extractPdfMetadata = async (file: File) => {
  const hash = await calculateHash(file);
  // Simulated extraction of PDF internal properties
  const isSuspicious = file.name.toLowerCase().includes('invoice') || file.name.toLowerCase().includes('urgent');
  
  return {
    version: "1.7 (Acrobat 8.x)",
    author: isSuspicious ? "Unknown / Generated" : "System Export",
    creator: "Microsoft Word 2019",
    pages: Math.floor(Math.random() * 5) + 1,
    hash,
    embeddedLinks: isSuspicious ? ["https://bit.ly/suspicious-shortlink"] : []
  };
};

export const extractApkMetadata = async (file: File) => {
  const commonPermissions = [
    "android.permission.INTERNET",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW"
  ];
  
  const hash = await calculateHash(file);
  const isSuspicious = file.size < 1000000 || file.name.toLowerCase().includes('crack');
  
  return {
    packageName: `com.app.${file.name.replace(/\.[^/.]+$/, "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase()}`,
    permissions: isSuspicious ? commonPermissions : commonPermissions.slice(0, 2),
    hash,
    certificate: "SHA256: " + hash.substring(0, 32).toUpperCase(),
  };
};

export const isValidUrl = (url: string) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};
