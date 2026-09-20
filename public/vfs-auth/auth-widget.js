(function (global) {
  "use strict";
  var KEY = "ecosystem.oauth.session.v1", base = global.VFS_AUTH_BASE_URL || "/auth/api", pending = null;
  function read() { try { return JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch (_) { return null; } }
  function write(v, source) { sessionStorage.setItem(KEY, JSON.stringify(v)); global.dispatchEvent(new CustomEvent("oauth:token", { detail: { user: v.user, source: source } })); return v; }
  function clear(reason) { sessionStorage.removeItem(KEY); global.dispatchEvent(new CustomEvent("oauth:logout", { detail: { reason: reason } })); }
  async function refresh() { if (pending) return pending; pending = fetch(base + "/refresh", { method: "POST", credentials: "include" }).then(async function(r){ if (!r.ok) { clear("refresh_failed"); throw new Error((await r.json().catch(function(){return {};})).error || "refresh_failed"); } return write(await r.json(), "refresh"); }).finally(function(){ pending = null; }); return pending; }
  async function token() { var s = read(); if (s && s.accessToken && Date.parse(s.expiresAt) > Date.now() + 15000) return s.accessToken; return (await refresh()).accessToken; }
  global.VfsAuth = Object.freeze({ login: function(){ var returnTo = /^https?:\/\//i.test(base) ? location.href : location.pathname + location.search + location.hash; location.assign(base + "/login?return_to=" + encodeURIComponent(returnTo)); }, logout: async function(){ var t=read(); if(t) await fetch(base+"/logout",{method:"POST",headers:{Authorization:"Bearer "+t.accessToken},credentials:"include"}).catch(function(){}); clear("logout"); }, refresh: refresh, getAccessToken: token, getUser: function(){ return read() && read().user; }, getSession: read, isAuthenticated: function(){ var s=read(); return !!(s && Date.parse(s.expiresAt)>Date.now()); } });
})(window);
