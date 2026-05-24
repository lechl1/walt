// walt GUI is a pure client-side SPA served as static files by waltd; it calls
// the daemon's REST + WS API at runtime, so there is no server side here.
export const ssr = false;
export const prerender = false;
export const trailingSlash = 'never';
