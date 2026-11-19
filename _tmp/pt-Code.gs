/* PRUEBA TÉCNICA — TURNOS SIN WHATSAPP (GERENCIA 19/11 13:24, OK de Dardo 13:23). Consultorio de prueba con datos inventados.
   Núcleo del servidor: el MISMO archivo corre en Apps Script (Code.gs lo envuelve) y en Node (las pruebas), con un "env" que pone
   lo que cambia entre los dos: guardar datos, fetch, hash, firma RSA, mail, hora, ids.
   1) Registro con Google: verifica el ID token de Google Identity Services contra las claves públicas de Google (jwks_uri),
      con la firma RSA hecha acá (Apps Script no trae verificación RSA). No usa el endpoint tokeninfo (Google lo indica para depurar).
      Alternativa: mail y clave.
   2) Sesión por aparato: el token de sesión queda atado al id del aparato; en otro aparato hay que iniciar sesión.
   3) Pedido pendiente; la profesional acepta o rechaza desde su panel. Formas de pago genéricas que elige cada profesional.
   4) Estado en Mis turnos y mail de respaldo al paciente (con control del cupo diario de mails).
   5) Aviso a la profesional por Firebase Cloud Messaging HTTP v1: con el JSON de una cuenta de servicio (JWT firmado acá) o, sin archivo de clave,
      con el token OAuth del dueño del script (ScriptApp.getOAuthToken, alcance firebase.messaging), si el proyecto de Apps Script es el de Firebase.
   El punto 6 (si el servidor no responde, WhatsApp) es de la página. */
var PT = (function(){
  var PAGOS = ['Particular', 'Obra social', 'Otra'];
  var GOOGLE_CERTS = 'https://www.googleapis.com/oauth2/v3/certs', GOOGLE_ISS = ['accounts.google.com', 'https://accounts.google.com'];
  var FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging', TOKEN_URL = 'https://oauth2.googleapis.com/token';

  /* ---------- utilidades ---------- */
  function b64uBytes(s){ s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while(s.length % 4) s += '=';
    var A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', out = [], buf = 0, bits = 0;
    for(var i = 0; i < s.length; i++){ var c = s.charAt(i); if(c === '=') break; var v = A.indexOf(c); if(v < 0) throw new Error('base64'); buf = (buf << 6) | v; bits += 6; if(bits >= 8){ bits -= 8; out.push((buf >> bits) & 255); } }
    return out; }
  function bytesB64u(b){ var A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', s = '', i;
    for(i = 0; i + 2 < b.length; i += 3){ var n = (b[i] << 16) | (b[i+1] << 8) | b[i+2]; s += A[n >> 18 & 63] + A[n >> 12 & 63] + A[n >> 6 & 63] + A[n & 63]; }
    if(b.length - i === 1){ var m = b[i] << 16; s += A[m >> 18 & 63] + A[m >> 12 & 63]; } else if(b.length - i === 2){ var o = (b[i] << 16) | (b[i+1] << 8); s += A[o >> 18 & 63] + A[o >> 12 & 63] + A[o >> 6 & 63]; }
    return s; }
  function utf8Bytes(s){ var e = unescape(encodeURIComponent(s)), o = []; for(var i = 0; i < e.length; i++) o.push(e.charCodeAt(i)); return o; }
  function bytesUtf8(b){ var s = ''; for(var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return decodeURIComponent(escape(s)); }
  function hex(b){ return b.map(function(x){ return ('0' + (x & 255).toString(16)).slice(-2); }).join(''); }
  function big(b){ return b.length ? BigInt('0x' + hex(b)) : BigInt(0); }
  function modpow(b, e, m){ var r = BigInt(1); b = b % m; while(e > BigInt(0)){ if(e & BigInt(1)) r = (r * b) % m; e >>= BigInt(1); b = (b * b) % m; } return r; }
  function limpio(s, n){ return String(s == null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, n || 120); }

  /* ---------- 1) ID token de Google: firma RS256 contra jwks_uri + iss, aud, exp, email verificado ---------- */
  function rsaVerifica(input, sigB64u, jwk, env){
    var n = big(b64uBytes(jwk.n)), e = big(b64uBytes(jwk.e)), k = b64uBytes(jwk.n).length;
    var m = modpow(big(b64uBytes(sigB64u)), e, n).toString(16); while(m.length < k * 2) m = '0' + m;
    var di = '3031300d060960864801650304020105000420' + env.sha256hex(input);            // DigestInfo SHA-256 (PKCS#1 v1.5)
    var esperado = '0001' + new Array(k - 3 - di.length / 2 + 1).join('ff') + '00' + di;
    return m === esperado; }
  function certs(env){ var c = env.cacheGet('gcerts'); if(c) return JSON.parse(c);
    var r = env.fetch(GOOGLE_CERTS, {method: 'get'}); if(r.code !== 200) throw new Error('No se pudieron leer las claves de Google');
    env.cachePut('gcerts', r.text, 3600); return JSON.parse(r.text); }
  function verificaGoogle(cred, env){
    var p = String(cred || '').split('.'); if(p.length !== 3) return {ok: false, msg: 'Token mal formado'};
    var h, c; try{ h = JSON.parse(bytesUtf8(b64uBytes(p[0]))); c = JSON.parse(bytesUtf8(b64uBytes(p[1]))); }catch(x){ return {ok: false, msg: 'Token ilegible'}; }
    if(h.alg !== 'RS256') return {ok: false, msg: 'Algoritmo no aceptado'};
    var k = (certs(env).keys || []).filter(function(x){ return x.kid === h.kid; })[0];
    if(!k){ env.cacheDel('gcerts'); k = (certs(env).keys || []).filter(function(x){ return x.kid === h.kid; })[0]; }   // Google rota las claves
    if(!k) return {ok: false, msg: 'Clave de Google desconocida'};
    if(!rsaVerifica(p[0] + '.' + p[1], p[2], k, env)) return {ok: false, msg: 'Firma inválida'};
    if(GOOGLE_ISS.indexOf(c.iss) < 0) return {ok: false, msg: 'Emisor inválido'};
    if(c.aud !== env.conf('GOOGLE_CLIENT_ID')) return {ok: false, msg: 'Token de otra app'};
    if(!(Number(c.exp) * 1000 > env.now())) return {ok: false, msg: 'Token vencido'};
    if(c.email_verified !== true && c.email_verified !== 'true') return {ok: false, msg: 'Mail de Google sin verificar'};
    return {ok: true, sub: String(c.sub), email: String(c.email || ''), nombre: String(c.name || '')}; }

  /* ---------- datos ---------- */
  function lee(env, k, d){ var v = env.get(k); return v ? JSON.parse(v) : d; }
  function guarda(env, k, v){ env.set(k, JSON.stringify(v)); }
  function conf(env){ return lee(env, 'conf', {pagos: PAGOS.slice(), nombre: 'Consultorio de prueba', profesional: 'Ana Prueba', fcm: []}); }
  function pacientes(env){ return lee(env, 'pacientes', {}); }
  function turnos(env){ return lee(env, 'turnos', []); }
  function hashClave(env, mail, clave){ return env.sha256hex('pt|' + mail.toLowerCase() + '|' + clave); }

  /* ---------- 2) sesión atada al aparato ---------- */
  function abreSesion(env, pid, dev){ var s = lee(env, 'sesiones', {}), t = env.uuid();
    Object.keys(s).forEach(function(k){ if(s[k].pid === pid && s[k].dev === dev) delete s[k]; });
    s[t] = {pid: pid, dev: String(dev), desde: env.now()}; guarda(env, 'sesiones', s); return t; }
  function sesion(env, q){ var s = lee(env, 'sesiones', {})[q.ses]; return s && s.dev === String(q.dev || '') ? s : null; }
  function perfil(p){ return {nombre: p.nombre, tel: p.tel, pago: p.pago, mail: p.mail, completo: !!(p.nombre && p.tel && p.pago)}; }

  /* ---------- 4) mail de respaldo ---------- */
  function mail(env, para, asunto, cuerpo){
    if(!para) return 'sin mail';
    if(env.mailCupo() < 1) return 'sin cupo';   // MailApp: cupo diario de la cuenta
    try{ env.mail(para, asunto, cuerpo); return 'enviado'; }catch(x){ return 'error: ' + x.message; } }

  /* ---------- 5) Firebase Cloud Messaging HTTP v1 con cuenta de servicio ---------- */
  function tokenFCM(env){
    var c = env.cacheGet('fcmtok'); if(c) return c;
    var sa = JSON.parse(env.conf('FCM_SERVICE_ACCOUNT') || 'null');
    if(!sa) return env.oauthToken ? env.oauthToken() : null;   // sin archivo de clave: el token del dueño del script (proyecto de Apps Script = proyecto de Firebase)
    var iat = Math.floor(env.now() / 1000), cab = bytesB64u(utf8Bytes(JSON.stringify({alg: 'RS256', typ: 'JWT'})));
    var cla = bytesB64u(utf8Bytes(JSON.stringify({iss: sa.client_email, scope: FCM_SCOPE, aud: TOKEN_URL, iat: iat, exp: iat + 3600})));
    var jwt = cab + '.' + cla + '.' + bytesB64u(env.rsaSign(cab + '.' + cla, sa.private_key));
    var r = env.fetch(TOKEN_URL, {method: 'post', contentType: 'application/x-www-form-urlencoded', payload: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt});
    if(r.code !== 200) throw new Error('Token de FCM: ' + r.code);
    var t = JSON.parse(r.text).access_token; env.cachePut('fcmtok', t, 3300); return t; }
  function avisaProfesional(env, titulo, texto){
    var cf = conf(env), sa = JSON.parse(env.conf('FCM_SERVICE_ACCOUNT') || 'null'), pid = sa ? sa.project_id : env.conf('FCM_PROJECT');
    if(!pid || !(cf.fcm || []).length) return 'sin configurar';
    var tok = tokenFCM(env), res = [], vivos = [];
    cf.fcm.forEach(function(d){
      // solo datos: el service worker de la página arma la notificación (no se registra el service worker de Firebase y no choca con el actual)
      var r = env.fetch('https://fcm.googleapis.com/v1/projects/' + pid + '/messages:send', {method: 'post', contentType: 'application/json', headers: {Authorization: 'Bearer ' + tok},
        payload: JSON.stringify({message: {token: d.token, data: {title: titulo, body: texto, url: env.conf('PANEL_URL') || ''}, webpush: {headers: {Urgency: 'high', TTL: '86400'}}}}), muteHttpExceptions: true});
      res.push(r.code); if(r.code !== 404 && !(r.code === 400 && /UNREGISTERED|INVALID_ARGUMENT/.test(r.text))) vivos.push(d);   // token dado de baja: se borra
    });
    if(vivos.length !== cf.fcm.length){ cf.fcm = vivos; guarda(env, 'conf', cf); }
    return res.join(','); }

  /* ---------- acciones ---------- */
  function esPro(env, q){ return q.clave && env.sha256hex('pro|' + q.clave) === env.conf('PRO_CLAVE_HASH'); }
  function handle(q, env){
    q = q || {}; var a = q.a;
    if(a === 'pub'){ var cf = conf(env); return {ok: true, nombre: cf.nombre, profesional: cf.profesional, pagos: cf.pagos, wa: env.conf('WA') || '', gid: env.conf('GOOGLE_CLIENT_ID') || '', fcm: JSON.parse(env.conf('FCM_WEB') || 'null')}; }
    if(a === 'google'){
      var v = verificaGoogle(q.cred, env); if(!v.ok) return v;
      var ps = pacientes(env), pid = 'g:' + v.sub; ps[pid] = ps[pid] || {nombre: v.nombre, mail: v.email, tel: '', pago: '', alta: env.now()}; guarda(env, 'pacientes', ps);
      return {ok: true, ses: abreSesion(env, pid, q.dev), perfil: perfil(ps[pid])}; }
    if(a === 'alta' || a === 'entrar'){
      var m = limpio(q.mail, 80).toLowerCase(); if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(m)) return {ok: false, msg: 'Revisá el mail'};
      if(String(q.clave || '').length < 6) return {ok: false, msg: 'La clave tiene que tener 6 caracteres o más'};
      var ps2 = pacientes(env), id = 'm:' + m, h = hashClave(env, m, String(q.clave));
      if(a === 'alta'){ if(ps2[id]) return {ok: false, msg: 'Ese mail ya está registrado: entrá con tu clave'}; ps2[id] = {nombre: '', mail: m, tel: '', pago: '', clave: h, alta: env.now()}; guarda(env, 'pacientes', ps2); }
      else if(!ps2[id] || ps2[id].clave !== h) return {ok: false, msg: 'Mail o clave incorrectos'};
      return {ok: true, ses: abreSesion(env, id, q.dev), perfil: perfil(ps2[id])}; }
    if(a === 'yo' || a === 'perfil' || a === 'pedir' || a === 'mis' || a === 'salir'){
      var s = sesion(env, q); if(!s) return {ok: false, sesion: false, msg: 'Iniciá sesión en este celular'};
      var ps3 = pacientes(env), p = ps3[s.pid];
      if(a === 'salir'){ var ss = lee(env, 'sesiones', {}); delete ss[q.ses]; guarda(env, 'sesiones', ss); return {ok: true}; }
      if(a === 'perfil'){ var pg = limpio(q.pago, 40); if(conf(env).pagos.indexOf(pg) < 0) return {ok: false, msg: 'Elegí una forma de pago'};
        var tel = limpio(q.tel, 30); if(String(tel).replace(/\D/g, '').length < 8) return {ok: false, msg: 'Revisá el teléfono'};
        if(!limpio(q.nombre, 80)) return {ok: false, msg: 'Poné tu nombre'};
        p.nombre = limpio(q.nombre, 80); p.tel = tel; p.pago = pg; guarda(env, 'pacientes', ps3); return {ok: true, perfil: perfil(p)}; }
      if(a === 'pedir'){
        if(!perfil(p).completo) return {ok: false, msg: 'Completá tus datos antes de pedir el turno'};
        if(!/^\d{4}-\d{2}-\d{2}$/.test(q.dia || '') || !/^\d{2}:\d{2}$/.test(q.hora || '')) return {ok: false, msg: 'Elegí día y horario'};
        var ts = turnos(env); if(ts.some(function(t){ return t.dia === q.dia && t.hora === q.hora && t.estado !== 'rechazado'; })) return {ok: false, msg: 'Ese horario ya está pedido: elegí otro'};
        var t = {id: env.uuid(), pid: s.pid, nombre: p.nombre, tel: p.tel, pago: p.pago, dia: q.dia, hora: q.hora, estado: 'pendiente', pedido: env.now()};
        ts.push(t); guarda(env, 'turnos', ts);
        var av; try{ av = avisaProfesional(env, 'Turno nuevo para aceptar', p.nombre + ' pidió el ' + q.dia + ' a las ' + q.hora); }catch(x){ av = 'error: ' + x.message; }
        var ml = mail(env, p.mail, 'Recibimos tu pedido de turno', 'Hola ' + p.nombre + '. Recibimos tu pedido de turno para el ' + q.dia + ' a las ' + q.hora + '. Te avisamos cuando lo confirmen.');
        return {ok: true, turno: t, aviso: av, mail: ml}; }
      if(a === 'mis') return {ok: true, perfil: perfil(p), turnos: turnos(env).filter(function(t){ return t.pid === s.pid; })};
      return {ok: true, perfil: perfil(p)}; }
    if(a === 'panel' || a === 'decidir' || a === 'pagos' || a === 'fcm'){
      if(!esPro(env, q)) return {ok: false, msg: 'Clave incorrecta'};
      var cf2 = conf(env);
      if(a === 'pagos'){ var el = (q.pagos || []).filter(function(x){ return PAGOS.indexOf(x) >= 0; }); if(!el.length) return {ok: false, msg: 'Elegí al menos una forma de pago'}; cf2.pagos = el; guarda(env, 'conf', cf2); }
      if(a === 'fcm'){ var tk = limpio(q.token, 400); if(tk && !cf2.fcm.some(function(d){ return d.token === tk; })) cf2.fcm.push({token: tk, ua: limpio(q.ua, 120), desde: env.now()}); guarda(env, 'conf', cf2); return {ok: true, aparatos: cf2.fcm.length}; }
      if(a === 'decidir'){
        if(['aceptado', 'rechazado'].indexOf(q.estado) < 0) return {ok: false, msg: 'Estado inválido'};
        var ts2 = turnos(env), t2 = ts2.filter(function(t){ return t.id === q.id; })[0]; if(!t2) return {ok: false, msg: 'Ese turno no existe'};
        if(t2.estado !== 'pendiente') return {ok: false, msg: 'Ese turno ya estaba ' + t2.estado};
        t2.estado = q.estado; t2.decidido = env.now(); guarda(env, 'turnos', ts2);
        var pp = pacientes(env)[t2.pid] || {};
        var ml2 = mail(env, pp.mail, q.estado === 'aceptado' ? 'Tu turno está confirmado' : 'Tu turno no se pudo confirmar',
          'Hola ' + t2.nombre + '. ' + (q.estado === 'aceptado' ? 'Tu turno del ' + t2.dia + ' a las ' + t2.hora + ' está confirmado.' : 'El turno que pediste para el ' + t2.dia + ' a las ' + t2.hora + ' no se pudo confirmar. Podés pedir otro horario.'));
        return {ok: true, turno: t2, mail: ml2}; }
      return {ok: true, pagos: cf2.pagos, aparatos: cf2.fcm.length, turnos: turnos(env)}; }
    return {ok: false, msg: 'Acción desconocida'}; }
  return {handle: handle, verificaGoogle: verificaGoogle, avisaProfesional: avisaProfesional, _b64: {b64uBytes: b64uBytes, bytesB64u: bytesB64u, utf8Bytes: utf8Bytes}, PAGOS: PAGOS};
})();


/* PRUEBA TÉCNICA turnos sin WhatsApp — envoltorio de Apps Script del núcleo (core.js va arriba en el mismo Code.gs; lo arma build_prueba_turnos.py).
   Propiedades del script (Configuración del proyecto > Propiedades): GOOGLE_CLIENT_ID, PRO_CLAVE_HASH, WA, PANEL_URL,
   FCM_WEB (config web de Firebase + vapidKey, JSON), FCM_PROJECT (id del proyecto de Firebase; el proyecto de Apps Script se pasa a ese proyecto de Google Cloud,
   así el token del dueño manda los avisos sin archivo de clave) o FCM_SERVICE_ACCOUNT (JSON de una cuenta de servicio; nunca en un repo ni en el chat).
   Los datos de la prueba van en propiedades del script con prefijo d_ (alcanza para una prueba; para producción, planilla). */
function env_(){
  var P = PropertiesService.getScriptProperties(), C = CacheService.getScriptCache();
  var bytes = function(b){ return b.map(function(x){ return x & 255; }); };
  return {
    get: function(k){ return P.getProperty('d_' + k); }, set: function(k, v){ P.setProperty('d_' + k, v); },
    conf: function(k){ return P.getProperty(k); },
    cacheGet: function(k){ return C.get(k); }, cachePut: function(k, v, s){ C.put(k, v, s); }, cacheDel: function(k){ C.remove(k); },
    fetch: function(url, o){ o = o || {}; var r = UrlFetchApp.fetch(url, {method: o.method || 'get', contentType: o.contentType, payload: o.payload, headers: o.headers, muteHttpExceptions: true}); return {code: r.getResponseCode(), text: r.getContentText()}; },
    sha256hex: function(s){ return bytes(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8)).map(function(x){ return ('0' + x.toString(16)).slice(-2); }).join(''); },
    rsaSign: function(s, pem){ return bytes(Utilities.computeRsaSha256Signature(s, pem)); },
    mail: function(to, subj, body){ MailApp.sendEmail(to, subj, body); }, mailCupo: function(){ return MailApp.getRemainingDailyQuota(); },
    oauthToken: function(){ return ScriptApp.getOAuthToken(); },
    now: function(){ return Date.now(); }, uuid: function(){ return Utilities.getUuid(); }
  };
}
function doPost(e){
  var q = {}; try{ q = JSON.parse(e.postData.contents); }catch(x){}
  var L = LockService.getScriptLock(); L.waitLock(20000);
  try{ return ContentService.createTextOutput(JSON.stringify(PT.handle(q, env_()))).setMimeType(ContentService.MimeType.JSON); }
  catch(x){ return ContentService.createTextOutput(JSON.stringify({ok: false, msg: 'Error del servidor'})).setMimeType(ContentService.MimeType.JSON); }
  finally{ L.releaseLock(); }
}
function doGet(){ return doPost({postData: {contents: JSON.stringify({a: 'pub'})}}); }
/* Para cargar la clave del panel de la profesional sin escribirla en ningún lado: correr una vez desde el editor y borrar el valor. */
function cargarClavePanel(){ var clave = ''; if(!clave) throw new Error('Poné la clave en la variable y volvé a correr; después borrala.');
  PropertiesService.getScriptProperties().setProperty('PRO_CLAVE_HASH', env_().sha256hex('pro|' + clave)); }
