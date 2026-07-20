export type EncodingMode = 
  | 'html-entity-dec' 
  | 'html-entity-hex' 
  | 'url-encode' 
  | 'double-url-encode' 
  | 'unicode-escape' 
  | 'base64-eval' 
  | 'hex-escape'
  | 'char-code';

export function encodePayload(payload: string, modes: EncodingMode[]): string {
  let result = payload;
  
  for (const mode of modes) {
    switch (mode) {
      case 'html-entity-dec':
        result = result.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
        break;
      case 'html-entity-hex':
        result = result.split('').map(c => `&#x${c.charCodeAt(0).toString(16)};`).join('');
        break;
      case 'url-encode':
        result = encodeURIComponent(result);
        break;
      case 'double-url-encode':
        result = encodeURIComponent(encodeURIComponent(result));
        break;
      case 'unicode-escape':
        result = result.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
        break;
      case 'hex-escape':
        result = result.split('').map(c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
        break;
      case 'base64-eval':
        result = `eval(atob('${btoa(result)}'))`;
        break;
      case 'char-code':
        const codes = Array.from(result).map(c => c.charCodeAt(0)).join(',');
        result = `String.fromCharCode(${codes})`;
        break;
    }
  }
  
  return result;
}