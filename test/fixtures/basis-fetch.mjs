// Test preload for the CLI's decision basis: replaces fetch with a controlled answer chosen by BASIS_FETCH,
// so no real network is used. 'stall' never answers; 'stall-body' sends headers, then a body that never ends;
// 'json' answers with the declaration in BASIS_FETCH_BODY. Each stalled answer holds a timer, as an open
// connection would, and releases it when the request is aborted.
const mode = process.env.BASIS_FETCH;
globalThis.fetch = async (url, init = {}) => {
  const hold = () => { const t = setInterval(() => {}, 1000); init.signal?.addEventListener('abort', () => clearInterval(t)); return t; };
  if (mode === 'stall') { hold(); return new Promise(() => {}); }
  if (mode === 'stall-body') {
    let t;
    const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{')); t = hold(); }, cancel() { clearInterval(t); } });
    return new Response(body, { status: 200 });
  }
  if (mode === 'json') return new Response(process.env.BASIS_FETCH_BODY, { status: 200 });
  throw new Error(`unexpected fetch ${url}`);
};
