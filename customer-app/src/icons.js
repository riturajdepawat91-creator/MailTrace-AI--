// Local Fluent-inspired SVG icon registry. No emoji, fonts, CDNs, or remote assets.
const paths = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  scan: '<circle cx="10.8" cy="10.8" r="6.5"/><path d="m16 16 4.5 4.5M3 8V4h4m10 0h4v4M3 16v4h4m10 0h4v-4"/>',
  mailbox: '<path d="M4 5h16v14H4zM4 12h4l2 3h4l2-3h4M8 8h.01M12 8h.01"/>',
  threat: '<path d="M12 3 20 6v5c0 5-3.2 8.5-8 11-4.8-2.5-8-6-8-11V6z"/><path d="M12 8v5m0 3h.01"/>',
  quarantine: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3"/>',
  privacy: '<path d="M12 3a7 7 0 0 0-7 7v2m14 0v-2a7 7 0 0 0-7-7M8 12v-2a4 4 0 0 1 8 0v5a4 4 0 0 1-8 0m-3-3v2a7 7 0 0 0 14 0v-2m-10 0v3a3 3 0 0 0 6 0v-5"/>',
  security: '<path d="M12 3 20 6v5c0 5-3.2 8.5-8 11-4.8-2.5-8-6-8-11V6z"/><path d="m8.5 12 2.3 2.3 4.8-5"/>',
  reports: '<path d="M6 3h9l5 5v13H6zM14 3v6h6M9 16h2m2-4h2m-6 8h6"/>',
  performance: '<path d="M4 19a9 9 0 1 1 16 0M12 12l4-4m-4 4-2 4m-2 3h8"/>',
  device: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.6.9l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.6-.9l-1.7.6-1.4-2.4 1.4-1.1a7 7 0 0 1 0-1.9L6.1 12l1.4-2.4 1.7.6a8 8 0 0 1 1.6-.9l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.6.9l1.7-.6 1.4 2.4-1.4 1.1a7 7 0 0 1-.1 1.9Z" transform="translate(-1 -1) scale(1.08)"/>',
  mailPlus: '<rect x="3" y="5" width="14" height="14" rx="2"/><path d="m4 7 6 5 6-5m4 6v6m-3-3h6"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 9h6v6H9zM9 2v4m6-4v4M9 18v4m6-4v4M2 9h4m-4 6h4m12-6h4m-4 6h4"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 9a7 7 0 0 1 12-2l2 2M4 15l2 2a7 7 0 0 0 12-2"/>',
  vault: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  success: '<circle cx="12" cy="12" r="9"/><path d="m8 12 2.5 2.5L16 9"/>',
  warning: '<path d="m12 3 10 18H2z"/><path d="M12 9v5m0 3h.01"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.6 2.6 0 1 1 4.6 1.7c-1.2 1-2.1 1.4-2.1 3m0 3h.01"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  arrow: '<path d="M5 12h14m-6-6 6 6-6 6"/>',
  gauge: '<path d="M4 19a9 9 0 1 1 16 0M12 12l4-4"/>',
  bank: '<path d="m3 9 9-6 9 6M5 10v8m5-8v8m4-8v8m5-8v8M3 21h18"/>',
  bell: '<path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 12h4"/>',
};

export function icon(name, size = 20, extraClass = '') {
  const body = paths[name] || paths.help;
  return `<svg class="app-icon ${extraClass}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}
