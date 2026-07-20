import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { randomBytes } from "crypto";

const DATA_DIR = join(process.cwd(), "data");
const LICENSE_FILE = join(DATA_DIR, "licenses.json");

export type LicensePlan = "trial" | "professional" | "lifetime";

export interface License {
  key: string;
  plan: LicensePlan;
  owner: string;
  createdAt: string;
  expiresAt: string | null; // null = lifetime
  active: boolean;
  note?: string;
}

interface LicenseStore {
  licenses: License[];
}

function load(): LicenseStore {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  if (!existsSync(LICENSE_FILE)) {
    save({ licenses: [] });
    return { licenses: [] };
  }
  try {
    return JSON.parse(readFileSync(LICENSE_FILE, "utf8")) as LicenseStore;
  } catch {
    return { licenses: [] };
  }
}

function save(store: LicenseStore): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(LICENSE_FILE, JSON.stringify(store, null, 2), "utf8");
}

function generateKey(): string {
  const hex = () => randomBytes(2).toString("hex").toUpperCase();
  return `XSSF-${hex()}-${hex()}-${hex()}-${hex()}`;
}

export function listLicenses(): License[] {
  return load().licenses;
}

export function generateLicense(
  plan: LicensePlan,
  owner: string,
  note?: string
): License {
  const now = new Date();
  let expiresAt: string | null = null;

  if (plan === "trial") {
    const exp = new Date(now);
    exp.setDate(exp.getDate() + 14);
    expiresAt = exp.toISOString();
  } else if (plan === "professional") {
    const exp = new Date(now);
    exp.setFullYear(exp.getFullYear() + 1);
    expiresAt = exp.toISOString();
  }
  // lifetime → null

  const license: License = {
    key: generateKey(),
    plan,
    owner: owner.trim() || "Unnamed",
    createdAt: now.toISOString(),
    expiresAt,
    active: true,
    note,
  };

  const store = load();
  store.licenses.push(license);
  save(store);
  return license;
}

export interface VerifyResult {
  valid: boolean;
  license?: License;
  reason?: string;
}

export function verifyLicense(key: string): VerifyResult {
  if (!key) return { valid: false, reason: "No key provided" };

  const store = load();
  const license = store.licenses.find(
    (l) => l.key.toUpperCase() === key.trim().toUpperCase()
  );

  if (!license) return { valid: false, reason: "License key not found" };
  if (!license.active) return { valid: false, reason: "License has been revoked" };

  if (license.expiresAt) {
    const exp = new Date(license.expiresAt);
    if (exp < new Date()) return { valid: false, reason: "License has expired" };
  }

  return { valid: true, license };
}

export function revokeLicense(key: string): boolean {
  const store = load();
  const idx = store.licenses.findIndex(
    (l) => l.key.toUpperCase() === key.trim().toUpperCase()
  );
  if (idx === -1) return false;
  store.licenses[idx].active = false;
  save(store);
  return true;
}

export function deleteLicense(key: string): boolean {
  const store = load();
  const before = store.licenses.length;
  store.licenses = store.licenses.filter(
    (l) => l.key.toUpperCase() !== key.trim().toUpperCase()
  );
  if (store.licenses.length === before) return false;
  save(store);
  return true;
}
