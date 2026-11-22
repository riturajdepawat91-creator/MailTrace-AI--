export const SCAN_RANGES = [1, 3, 7, 14, 30];
export const SCAN_LIMITS = { maxEmails: 5000, maxSizeMb: 250 };

export function normalizeScanConfig(config) {
  const days = Number(config.days);
  const maxEmails = Number(config.maxEmails);
  const maxSizeMb = Number(config.maxSizeMb);
  return {
    days: SCAN_RANGES.includes(days) ? days : 1,
    mailbox: String(config.mailbox || 'none'),
    folder: String(config.folder || 'inbox'),
    mode: config.mode === 'deep' ? 'deep' : 'standard',
    maxEmails: Number.isInteger(maxEmails) ? Math.max(1, Math.min(maxEmails, SCAN_LIMITS.maxEmails)) : 500,
    maxSizeMb: Number.isInteger(maxSizeMb) ? Math.max(1, Math.min(maxSizeMb, SCAN_LIMITS.maxSizeMb)) : 50,
  };
}

export function summarizeScanConfig(input) {
  const config = normalizeScanConfig(input);
  const mailbox = config.mailbox === 'none' ? 'No mailbox selected' : config.mailbox;
  return `${config.days}-day range · ${mailbox} · ${config.folder} · ${config.mode === 'deep' ? 'Deep scan' : 'Standard scan'} · up to ${config.maxEmails} messages / ${config.maxSizeMb} MB`;
}

export function canRunCustomerScan({ serviceAvailable = false } = {}) {
  return serviceAvailable === true;
}
