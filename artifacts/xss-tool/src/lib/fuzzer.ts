export type FuzzOption = 'case' | 'tag-swap' | 'attr-swap' | 'whitespace' | 'comment' | 'null-byte' | 'double-encode';

export interface FuzzOptions {
  base: string;
  modes: FuzzOption[];
  count: number;
}

const tags = ['script', 'img', 'svg', 'iframe', 'body', 'details', 'video', 'audio'];
const attrs = ['onerror', 'onload', 'onfocus', 'onmouseover', 'ontoggle'];

export function generateFuzzVariants(options: FuzzOptions): string[] {
  const { base, modes, count } = options;
  const results = new Set<string>();
  
  if (modes.length === 0 || count <= 0) return [base];
  
  results.add(base);
  let attempts = 0;
  
  while (results.size < count && attempts < count * 10) {
    attempts++;
    let variant = base;
    
    for (const mode of modes) {
      if (Math.random() > 0.5) continue; 
      
      switch (mode) {
        case 'case':
          variant = variant.split('').map(c => 
            Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()
          ).join('');
          break;
        case 'tag-swap':
          for (const t of tags) {
            if (variant.toLowerCase().includes(t)) {
              variant = variant.replace(new RegExp(t, 'ig'), tags[Math.floor(Math.random() * tags.length)]);
            }
          }
          break;
        case 'attr-swap':
          for (const a of attrs) {
            if (variant.toLowerCase().includes(a)) {
              variant = variant.replace(new RegExp(a, 'ig'), attrs[Math.floor(Math.random() * attrs.length)]);
            }
          }
          break;
        case 'whitespace':
          variant = variant.replace(/ /g, [' ', '\t', '\n', '\r'][Math.floor(Math.random() * 4)]);
          break;
        case 'comment':
          variant = variant.replace(/</g, '</* */').replace(/>/g, '/* */>');
          break;
        case 'null-byte':
          variant = variant.replace(/</g, '<\0');
          break;
        case 'double-encode':
          variant = encodeURIComponent(encodeURIComponent(variant));
          break;
      }
    }
    
    if (variant !== base) {
      results.add(variant);
    }
  }
  
  return Array.from(results).slice(0, count);
}