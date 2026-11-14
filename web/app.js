'use strict';
/* Crimson dashboard — vanilla JS, no build step, strict CSP friendly (no inline handlers/styles). */

const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = { me: null, meta: null, lang: 'en', openF: new Set(), watching: null, poll: null, tid: null, data: null, focus: null };
try { state.lang = localStorage.getItem('crimson.lang') || (navigator.language || '').toLowerCase().startsWith('az') ? 'az' : 'en'; if (localStorage.getItem('crimson.lang')) state.lang = localStorage.getItem('crimson.lang'); } catch { }

/* ---------- i18n ---------- */
const I = {
  en: {
    tagline: 'Cyber security for organisations <em>without</em> a security team.',
    heroP: 'Crimson scans your public systems, explains every problem in plain language, and a real security engineer fixes what you choose and checks the result by hand.',
    b1: 'Automated scan in about a minute', b2: 'Plain-language explanations, not CVE lists', b3: 'A real engineer fixes what you choose, then verifies it', b4: 'Built for clinics, schools, municipalities and small businesses',
    signin: 'Sign in', create: 'Create account', email: 'E-mail', password: 'Password', pw10: 'At least 10 characters', yourName: 'Your name', org: 'Organisation', sector: 'Sector',
    authFine: 'Only add systems you own or are authorised to test.',
    signout: 'Sign out', mySites: 'My sites', queue: 'Work queue', allCust: 'All customers', audit: 'Audit log',
    sitesSub: 'Add the websites and servers you want checked. Crimson only scans systems you can prove you control.',
    addSite: 'Add site', siteHolder: 'example.com', add: 'Add',
    noSites: 'No sites yet', noSitesP: 'Add your first website or server above to start.',
    notVerified: 'Ownership not verified', scanning: 'Scanning…', neverScanned: 'Not scanned yet', lastScan: 'Last scan', manualReview: 'Manual review',
    back: '← All sites', runScan: 'Run scan', rescan: 'Rescan', deep: 'Deep scan', reqAll: 'Ask the team to fix everything', report: 'Report (print / PDF)',
    needs: 'Needs attention', handled: 'Handled', nothingOpen: 'Nothing needs attention right now.', noScanYet: 'Run your first scan to see results.',
    howFix: 'How to fix', evidence: 'Evidence', explainAI: 'Explain with AI', aiTitle: 'AI explanation', thinking: 'Thinking…',
    reqFix: 'Ask the team to fix this', cancelReq: 'Cancel request', accept: 'Accept the risk', reopen: 'Reopen',
    comments: 'Conversation', writeComment: 'Write a message…', send: 'Send', save: 'Save', note: 'Note (visible to customer)',
    verifyTitle: 'Prove you control this site', verifyP: 'So that Crimson cannot be used against someone else, scanning starts only after you prove ownership. Use either method:',
    verifyDns: 'Add a DNS TXT record on {host} with the value', verifyFile: 'or publish a text file at {path} containing exactly', checkNow: 'Check now',
    verifyFail: 'Not found yet. DNS changes can take a few minutes.', verifyOk: 'Ownership verified', forceTitle: 'Staff: confirm manually', forceHolder: 'How was ownership confirmed? (e.g. signed authorisation letter)', confirm: 'Confirm',
    checklistTitle: 'Manual review by the Crimson team', checklistP: 'What a scanner cannot see: your internal network, backups, people and processes. Our engineers go through these with you.',
    history: 'Scan history', date: 'Date', score: 'Score', newN: 'New', resolvedN: 'Resolved', reopenedN: 'Reopened',
    addManual: 'Add a manual finding', mTitle: 'Title', mPlain: 'What it means (plain language)', mFix: 'How to fix', severity: 'Severity',
    lastLog: 'Scan log', scanDone: 'Scan finished', scanFail: 'Scan failed', requested: 'Fix requested',
    qTitle: 'Work queue', qSub: 'What customers asked the team to fix, and what is waiting for a check.', qEmpty: 'The queue is empty', qEmptyP: 'When customers request fixes, they appear here.',
    stCustomers: 'Customers', stSites: 'Sites', stQueue: 'In queue', stPending: 'Awaiting verification', problem: 'Problem', customer: 'Customer', site: 'Site', status: 'Status', updated: 'Updated',
    pendingTitle: 'Sites waiting for ownership verification', openCol: 'Open', grade: 'Grade', who: 'Who', action: 'Action', details: 'Details', when: 'When',
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
    open: 'Open', in_progress: 'In progress', fixed: 'Fixed, awaiting check', verified: 'Verified fixed', resolved: 'No longer detected', accepted: 'Risk accepted',
    customerRole: 'Customer', staffRole: 'Crimson team', systemRole: 'System',
    general: 'General', healthcare: 'Healthcare', education: 'Education', government: 'Government', retail: 'Retail', finance: 'Finance', ngo: 'Non-profit',
    reqSent: 'Request sent to the team', done: 'Saved', fixesRequested: '{n} problem(s) sent to the team', needsVerify: 'Verify ownership first', aiOff: 'AI explanations are not enabled on this server',
    demoTitle: 'Demo site controls', demoP: 'Simulates the engineer applying the fixes on the bundled demo clinic site, then rescan to verify.', demoFix: 'Apply fixes on demo site', demoBreak: 'Break it again', demoDone: 'Done. Now rescan the site.',
    forgot: 'Forgot password?', forgotTitle: 'Reset your password', forgotP: 'Enter your account e-mail and we will send you a reset link.', sendLink: 'Send reset link',
    forgotSent: 'If an account exists for that e-mail, a reset link is on its way. It is valid for 1 hour.', backSignin: '← Back to sign in', resetTitle: 'Choose a new password', setPw: 'Set new password', resetDone: 'Password updated. Sign in with your new password.',
    sbTitle: 'Public sandbox', sbP: 'Everything here is demo data and can be reset at any time. Sign in with a demo account. Scanning a real system still requires proving you own it.', sbBar: 'Public sandbox · demo data · scanning real systems requires proof of ownership', tryDemo: 'Try the demo clinic site:',
    scanCountdown: 'running…', deepNote: 'needs nuclei installed on the server',
  },
  az: {
    tagline: 'Təhlükəsizlik komandası olmayan təşkilatlar üçün <em>kibertəhlükəsizlik</em>.',
    heroP: 'Crimson açıq sistemlərinizi skan edir, hər problemi sadə dildə izah edir; real təhlükəsizlik mühəndisi seçdiyiniz problemləri həll edir və nəticəni əl ilə yoxlayır.',
    b1: 'Təxminən bir dəqiqəyə avtomatik skan', b2: 'CVE siyahısı yox, sadə dildə izahat', b3: 'Real mühəndis seçdiyinizi düzəldir, sonra yoxlayır', b4: 'Klinikalar, məktəblər, bələdiyyələr və kiçik bizneslər üçün',
    signin: 'Daxil ol', create: 'Hesab yarat', email: 'E-poçt', password: 'Parol', pw10: 'Ən azı 10 simvol', yourName: 'Adınız', org: 'Təşkilat', sector: 'Sahə',
    authFine: 'Yalnız sahibi olduğunuz və ya yoxlamağa icazəniz olan sistemləri əlavə edin.',
    signout: 'Çıxış', mySites: 'Saytlarım', queue: 'İş növbəsi', allCust: 'Bütün müştərilər', audit: 'Audit jurnalı',
    sitesSub: 'Yoxlanmasını istədiyiniz sayt və serverləri əlavə edin. Crimson yalnız nəzarətinizdə olduğunu sübut etdiyiniz sistemləri skan edir.',
    addSite: 'Sayt əlavə et', siteHolder: 'example.com', add: 'Əlavə et',
    noSites: 'Hələ sayt yoxdur', noSitesP: 'Başlamaq üçün yuxarıda ilk saytınızı və ya serverinizi əlavə edin.',
    notVerified: 'Sahiblik təsdiqlənməyib', scanning: 'Skan gedir…', neverScanned: 'Hələ skan olunmayıb', lastScan: 'Son skan', manualReview: 'Əl ilə yoxlama',
    back: '← Bütün saytlar', runScan: 'Skan et', rescan: 'Yenidən skan et', deep: 'Dərin skan', reqAll: 'Komandadan hamısını düzəltməyi xahiş et', report: 'Hesabat (çap / PDF)',
    needs: 'Diqqət tələb edir', handled: 'Həll olunanlar', nothingOpen: 'Hazırda diqqət tələb edən heç nə yoxdur.', noScanYet: 'Nəticələri görmək üçün ilk skanı işə salın.',
    howFix: 'Necə düzəltməli', evidence: 'Sübut', explainAI: 'AI ilə izah et', aiTitle: 'AI izahı', thinking: 'Düşünür…',
    reqFix: 'Komandadan bunu düzəltməyi xahiş et', cancelReq: 'Xahişi ləğv et', accept: 'Riski qəbul et', reopen: 'Yenidən aç',
    comments: 'Yazışma', writeComment: 'Mesaj yazın…', send: 'Göndər', save: 'Saxla', note: 'Qeyd (müştəri görəcək)',
    verifyTitle: 'Bu sayta nəzarətinizi sübut edin', verifyP: 'Crimson başqasına qarşı istifadə oluna bilməsin deyə skan yalnız sahibliyi sübut etdikdən sonra başlayır. İki üsuldan birini seçin:',
    verifyDns: '{host} üçün DNS TXT qeydi əlavə edin, dəyəri', verifyFile: 'və ya {path} ünvanında dəqiq bu məzmunlu mətn faylı yerləşdirin', checkNow: 'İndi yoxla',
    verifyFail: 'Hələ tapılmadı. DNS dəyişiklikləri bir neçə dəqiqə çəkə bilər.', verifyOk: 'Sahiblik təsdiqləndi', forceTitle: 'Staff: əl ilə təsdiqlə', forceHolder: 'Sahiblik necə təsdiqləndi? (məs. imzalı icazə məktubu)', confirm: 'Təsdiqlə',
    checklistTitle: 'Crimson komandasının əl ilə yoxlaması', checklistP: 'Skanerin görə bilmədikləri: daxili şəbəkəniz, ehtiyat nüsxələr, insanlar və proseslər. Mühəndislərimiz bunları sizinlə birgə yoxlayır.',
    history: 'Skan tarixçəsi', date: 'Tarix', score: 'Bal', newN: 'Yeni', resolvedN: 'Həll olunub', reopenedN: 'Yenidən açılıb',
    addManual: 'Əl ilə tapıntı əlavə et', mTitle: 'Başlıq', mPlain: 'Nə deməkdir (sadə dildə)', mFix: 'Necə düzəltməli', severity: 'Ciddilik',
    lastLog: 'Skan jurnalı', scanDone: 'Skan başa çatdı', scanFail: 'Skan alınmadı', requested: 'Düzəliş istənilib',
    qTitle: 'İş növbəsi', qSub: 'Müştərilərin komandadan düzəltməsini istədikləri və yoxlama gözləyənlər.', qEmpty: 'Növbə boşdur', qEmptyP: 'Müştərilər düzəliş istədikdə burada görünəcək.',
    stCustomers: 'Müştərilər', stSites: 'Saytlar', stQueue: 'Növbədə', stPending: 'Təsdiq gözləyən', problem: 'Problem', customer: 'Müştəri', site: 'Sayt', status: 'Status', updated: 'Yenilənib',
    pendingTitle: 'Sahiblik təsdiqi gözləyən saytlar', openCol: 'Açıq', grade: 'Qiymət', who: 'Kim', action: 'Əməliyyat', details: 'Detallar', when: 'Nə vaxt',
    critical: 'Kritik', high: 'Yüksək', medium: 'Orta', low: 'Aşağı', info: 'Məlumat',
    open: 'Açıq', in_progress: 'İcrada', fixed: 'Düzəldilib, yoxlama gözlənilir', verified: 'Düzəliş təsdiqlənib', resolved: 'Artıq aşkarlanmır', accepted: 'Risk qəbul edilib',
    customerRole: 'Müştəri', staffRole: 'Crimson komandası', systemRole: 'Sistem',
    general: 'Ümumi', healthcare: 'Səhiyyə', education: 'Təhsil', government: 'Dövlət', retail: 'Pərakəndə', finance: 'Maliyyə', ngo: 'Qeyri-kommersiya',
    reqSent: 'Xahiş komandaya göndərildi', done: 'Saxlanıldı', fixesRequested: '{n} problem komandaya göndərildi', needsVerify: 'Əvvəlcə sahibliyi təsdiqləyin', aiOff: 'Bu serverdə AI izahı aktiv deyil',
    demoTitle: 'Demo sayt idarəsi', demoP: 'Mühəndisin demo klinika saytında düzəlişləri tətbiq etməsini simulyasiya edir, sonra yoxlamaq üçün yenidən skan edin.', demoFix: 'Demo saytda düzəlişləri tətbiq et', demoBreak: 'Yenidən poz', demoDone: 'Hazırdır. İndi saytı yenidən skan edin.',
    forgot: 'Parolu unutmusunuz?', forgotTitle: 'Parolu sıfırlayın', forgotP: 'Hesabın e-poçtunu yazın, sizə sıfırlama linki göndərəcəyik.', sendLink: 'Sıfırlama linki göndər',
    forgotSent: 'Bu e-poçt üçün hesab varsa, sıfırlama linki göndərildi. Link 1 saat etibarlıdır.', backSignin: '← Girişə qayıt', resetTitle: 'Yeni parol seçin', setPw: 'Yeni parolu təyin et', resetDone: 'Parol yeniləndi. Yeni parolla daxil olun.',
    sbTitle: 'Public sandbox', sbP: 'Buradakı hər şey demo məlumatdır və istənilən vaxt sıfırlana bilər. Demo hesabla daxil olun. Real sistemi skan etmək üçün yenə sahibliyi sübut etmək lazımdır.', sbBar: 'Public sandbox · demo məlumat · real sistemləri skan üçün sahibliyi sübut etmək lazımdır', tryDemo: 'Demo klinika saytını sınayın:',
    scanCountdown: 'gedir…', deepNote: 'serverdə nuclei quraşdırılmalıdır',
  },
};
const t = (k, v) => { let s = (I[state.lang] && I[state.lang][k]) ?? I.en[k] ?? k; if (v) for (const [a, b] of Object.entries(v)) s = s.split('{' + a + '}').join(b); return s; };
const ft = f => (f.i18n && (f.i18n[state.lang] || f.i18n.en)) || { title: '', plain: '', fix: '' };
const when = x => x ? new Date(x).toLocaleString(state.lang === 'az' ? 'az' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '';

/* ---------- helpers ---------- */
async function api(method, url, body) {
  const r = await fetch(url, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  let d = {}; try { d = await r.json(); } catch { }
  if (!r.ok) { const e = new Error(d.error || r.statusText); e.status = r.status; throw e; }
  return d;
}
let toastT;
function toast(msg, bad) {
  const el = $('#toast'); el.textContent = msg; el.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastT); toastT = setTimeout(() => el.className = '', 3200);
}
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { if (e.status === 401) { state.me = null; render(); } else toast(e.message, true); } };

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const isActive = f => (f.present || f.manual) && !['verified', 'resolved', 'accepted', 'fixed'].includes(f.status);
const staff = () => state.me && state.me.role === 'staff';

function ring(score, grade, scanned, big) {
  const size = big ? 150 : 92, r = big ? 64 : 38, sw = big ? 11 : 8, c = 2 * Math.PI * r;
  const off = scanned ? c * (1 - score / 100) : c;
  return `<div class="ring ${big ? 'big' : ''} ${scanned ? 'grade-' + grade : 'none'}" aria-label="${scanned ? score + '/100' : ''}">
    <svg viewBox="0 0 ${size} ${size}"><circle class="tr" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke-width="${sw}"/>
    <circle class="pr" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke-width="${sw}" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/></svg>
    <div class="lab"><b>${scanned ? grade : '–'}</b><span>${scanned ? score + '/100' : ''}</span></div></div>`;
}
const chips = counts => SEV.filter(s => counts && counts[s]).map(s => `<span class="chip ${s}"><i></i>${t(s)} ${counts[s]}</span>`).join('');
const logoSvg = '<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#e11d48"/><path d="M16 6 7 10v6c0 5 4 8.5 9 10 5-1.5 9-5 9-10v-6z" fill="none" stroke="#fff" stroke-width="2.5" stroke-linejoin="round"/></svg>';

/* ---------- shell ---------- */
function shell(inner, active) {
  const nav = staff()
    ? [['#/queue', 'queue'], ['#/all', 'allCust'], ['#/audit', 'audit']]
    : [['#/', 'mySites']];
  return `${state.meta && state.meta.sandbox ? `<div class="sbbar">${t('sbBar')}</div>` : ''}<header class="top"><a class="logo" href="#/">${logoSvg}CRIMSON</a>
    <nav class="nav">${nav.map(([h, k]) => `<a href="${h}" class="${active === h ? 'on' : ''}">${t(k)}</a>`).join('')}</nav><div class="sp"></div>
    ${langSwitch()}
    <div class="who"><b>${esc(state.me.name || state.me.email)}${staff() ? '<span class="badge-staff">STAFF</span>' : ''}</b>${esc(state.me.org ? state.me.org.name : state.me.email)}</div>
    <button class="btn small ghost" data-act="logout">${t('signout')}</button></header><main>${inner}</main>`;
}
const langSwitch = () => `<div class="lang" role="group" aria-label="Language">${['en', 'az'].map(l => `<button data-act="lang" data-v="${l}" class="${state.lang === l ? 'on' : ''}">${l.toUpperCase()}</button>`).join('')}</div>`;

/* ---------- auth ---------- */
let authTab = 'login';
function renderAuth() {
  const check = '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 10.5l4 4 8-9"/></svg>';
  const sectors = (state.meta ? state.meta.sectors : ['general', 'healthcare']).map(s => `<option value="${s}">${t(s)}</option>`).join('');
  const signup = !(state.meta && state.meta.signup === false);
  if (authTab === 'register' && !signup) authTab = 'login';
  const tabsOn = authTab === 'login' || authTab === 'register';
  const sb = state.meta && state.meta.sandbox;
  const sbBox = sb ? `<div class="sbbox"><b>${t('sbTitle')}</b><p>${t('sbP')}</p>${(state.meta.accounts || []).map(a => `<div class="sbrow"><span>${t(a.role === 'staff' ? 'staffRole' : 'customerRole')}</span><code>${esc(a.email)}</code><code>${esc(a.password)}</code></div>`).join('')}</div>` : '';
  const emailF = `<label for="a-email">${t('email')}</label><input id="a-email" name="email" type="email" autocomplete="email" required>`;
  let body;
  if (authTab === 'forgot') body = `<h2 class="ftitle">${t('forgotTitle')}</h2><p class="fine">${t('forgotP')}</p>${emailF}`;
  else if (authTab === 'reset') body = `<h2 class="ftitle">${t('resetTitle')}</h2><label for="a-pw">${t('password')}</label><input id="a-pw" name="password" type="password" autocomplete="new-password" minlength="10" placeholder="${t('pw10')}" required>`;
  else body = `${authTab === 'register' ? `<label for="a-name">${t('yourName')}</label><input id="a-name" name="name" type="text" autocomplete="name" required>
      <label for="a-org">${t('org')}</label><input id="a-org" name="org" type="text" autocomplete="organization" required>
      <label for="a-sec">${t('sector')}</label><select id="a-sec" name="sector">${sectors}</select>` : ''}
      ${emailF}
      <label for="a-pw">${t('password')}</label><input id="a-pw" name="password" type="password" autocomplete="${authTab === 'login' ? 'current-password' : 'new-password'}" ${authTab === 'register' ? 'minlength="10" placeholder="' + t('pw10') + '"' : ''} required>
      ${authTab === 'login' ? `<button type="button" class="linkbtn" data-act="tab" data-v="forgot">${t('forgot')}</button>` : ''}`;
  const submitLabel = { login: 'signin', register: 'create', forgot: 'sendLink', reset: 'setPw' }[authTab] || 'signin';
  const back = authTab === 'forgot' ? `<button type="button" class="linkbtn" data-act="tab" data-v="login">${t('backSignin')}</button>` : authTab === 'reset' ? `<a class="linkbtn" href="#/">${t('backSignin')}</a>` : '';
  $('#app').innerHTML = `<div class="auth"><section class="hero"><div class="logo">${logoSvg}CRIMSON</div>
    <h1>${t('tagline')}</h1><p>${t('heroP')}</p>
    <ul>${['b1', 'b2', 'b3', 'b4'].map(k => `<li>${check}<span>${t(k)}</span></li>`).join('')}</ul></section>
    <section class="formwrap"><div class="form">${sbBox}
    <div class="lang" role="group">${['en', 'az'].map(l => `<button data-act="lang" data-v="${l}" class="${state.lang === l ? 'on' : ''}">${l.toUpperCase()}</button>`).join('')}</div>
    ${tabsOn ? `<div class="tabs" role="tablist" id="authtabs"><button data-act="tab" data-v="login" class="${authTab === 'login' ? 'on' : ''}">${t('signin')}</button>${signup ? `<button data-act="tab" data-v="register" class="${authTab === 'register' ? 'on' : ''}">${t('create')}</button>` : ''}</div>` : ''}
    <form data-form="${authTab}" autocomplete="on">
      ${body}
      <div class="err" id="autherr" role="alert"></div>
      <button class="btn primary" style="width:100%;justify-content:center;margin-top:6px" type="submit">${t(submitLabel)}</button>
      ${back}
    </form><p class="fine">${t('authFine')}</p></div></section></div>`;
}

/* ---------- customer: site list ---------- */
async function showHome() {
  const list = await api('GET', '/api/targets');
  const cards = list.length ? `<div class="grid g2">${list.map(targetCard).join('')}</div>`
    : `<div class="card empty"><h3>${t('noSites')}</h3><p>${t('noSitesP')}</p></div>`;
  $('#app').innerHTML = shell(`<div class="page-h"><div><h1>${t('mySites')}</h1><p>${t('sitesSub')}</p></div></div>
    <form class="card" data-form="addtarget" style="display:flex;gap:10px;align-items:center;margin-bottom:18px"><input type="text" name="host" placeholder="${t('siteHolder')}" aria-label="${t('addSite')}" required autocomplete="off" spellcheck="false"><button class="btn primary" type="submit">${t('add')}</button></form>${state.meta && state.meta.sandbox ? `<p class="fine">${t('tryDemo')} <code>127.0.0.1:8081</code></p>` : ''}${cards}`, '#/');
}
function targetCard(s) {
  const status = !s.verified ? `<span class="pill warn">${t('notVerified')}</span>` : s.scanning ? `<span class="pill">${t('scanning')}</span>` : '';
  return `<a class="card tcard" href="#/t/${esc(s.id)}">${ring(s.score, s.grade, s.scanned, false)}
    <div><h3>${esc(s.host)}</h3><div class="sub">${s.scanned ? t('lastScan') + ': ' + when(s.lastScan) : t('neverScanned')}</div>
    <div class="chips">${status}${chips(s.counts)}${s.requested ? `<span class="pill requested">${t('requested')}: ${s.requested}</span>` : ''}${s.checkTotal ? `<span class="chip"><i></i>${t('manualReview')} ${s.checkDone}/${s.checkTotal}</span>` : ''}</div></div></a>`;
}

/* ---------- target detail ---------- */
async function showTarget(id, keep) {
  const y = window.scrollY;
  state.tid = id;
  state.data = await api('GET', '/api/targets/' + encodeURIComponent(id));
  state.data.findings = state.data.findings || []; state.data.scans = state.data.scans || [];
  state.data.target.checklist = state.data.target.checklist || [];
  renderTarget();
  if (keep) window.scrollTo(0, y);
  if (state.focus) { const el = document.getElementById('f-' + state.focus); if (el) el.scrollIntoView({ block: 'center' }); state.focus = null; }
  const d = state.data;
  if (d.summary.scanning && state.watching !== d.target.lastScanId) watchScan(d.target.lastScanId);
}

function renderTarget() {
  const { summary: s, target, org, findings, scans } = state.data;
  const active = findings.filter(isActive), handled = findings.filter(f => !isActive(f));
  const last = scans[0];
  const canScan = s.verified && !s.scanning;
  const deepBox = state.meta && state.meta.deep ? `<label class="check-inline"><input type="checkbox" id="deepchk"> ${t('deep')}</label>` : '';
  const head = `<a class="crumb" href="${staff() ? '#/all' : '#/'}">${staff() ? '← ' + t('allCust') : t('back')}</a>
    <section class="card thead">${ring(s.score, s.grade, s.scanned, true)}
      <div class="info"><h1>${esc(target.host)}</h1>
        <div style="color:var(--muted);margin-top:4px">${esc(org.name)} · ${t(org.sector)}</div>
        <div class="chips">${!s.verified ? `<span class="pill warn">${t('notVerified')}</span>` : ''}${chips(s.counts)}${s.requested ? `<span class="pill requested">${t('requested')}: ${s.requested}</span>` : ''}${s.inProgress ? `<span class="pill in_progress">${t('in_progress')}: ${s.inProgress}</span>` : ''}${s.fixed ? `<span class="pill fixed">${t('fixed')}: ${s.fixed}</span>` : ''}</div>
        <div class="actions"><button class="btn primary" data-act="scan" ${canScan ? '' : 'disabled'}>${s.scanning ? t('scanning') : s.scanned ? t('rescan') : t('runScan')}</button>${deepBox}
          ${!staff() && active.some(f => f.status === 'open') ? `<button class="btn" data-act="reqall">${t('reqAll')}</button>` : ''}
          ${s.scanned || findings.length ? `<a class="btn" href="/report/${esc(target.id)}?lang=${state.lang}" target="_blank" rel="noopener">${t('report')}</a>` : ''}</div></div></section>`;

  const term = (s.scanning || last && last.log && last.log.length) ? `<div class="card"><h3 style="font-size:14px;color:var(--muted)">${t('lastLog')}</h3><div class="term" id="term">${termHtml(last, s.scanning)}</div></div>` : '';
  const verify = !s.verified ? verifyCard(target) : '';

  const needs = `<h2 class="sec">${t('needs')} <small>${active.length}</small></h2>` +
    (active.length ? active.map(f => findingCard(f)).join('') : `<div class="card empty"><p>${s.scanned ? t('nothingOpen') : t('noScanYet')}</p></div>`);
  const done = handled.length ? `<h2 class="sec">${t('handled')} <small>${handled.length}</small></h2>${handled.map(f => findingCard(f)).join('')}` : '';

  const hist = scans.length ? `<h2 class="sec">${t('history')}</h2><div class="card"><table><thead><tr><th>${t('date')}</th><th>${t('score')}</th><th>${t('newN')}</th><th>${t('resolvedN')}</th><th>${t('reopenedN')}</th></tr></thead><tbody>
    ${scans.filter(x => x.status !== 'running').map(x => `<tr><td>${when(x.started)}</td><td>${x.status === 'done' ? esc(x.grade) + ' · ' + x.score : '<span class="pill requested">' + t('scanFail') + '</span>'}</td><td>${x.new || 0}</td><td>${x.resolved || 0}</td><td>${x.reopened || 0}</td></tr>`).join('')}</tbody></table></div>` : '';

  $('#app').innerHTML = shell(head + verify + term + needs + done + checklistCard(target) + (staff() ? demoCard(target) + staffTools(target) : '') + hist, staff() ? '#/all' : '#/');
}

function termHtml(sc, running) {
  const lines = sc && sc.log ? sc.log.map(l => `<div>${esc(l)}</div>`).join('') : '';
  return lines + (running ? '<div><span class="cursor"></span></div>' : '');
}

function verifyCard(target) {
  const host = target.host.split(':')[0];
  const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(host);
  const scheme = /:(443|8443)$/.test(target.host) ? 'https' : 'http';
  const path = '/.well-known/crimson-verify.txt';
  return `<div class="card"><h2 style="font-size:17px">${t('verifyTitle')}</h2><p style="color:var(--muted)">${t('verifyP')}</p>
    <ol class="steps">${isIP ? '' : `<li>${t('verifyDns', { host: '<span class="code">' + esc(host) + '</span>' })}: <span class="code">crimson-verify=${esc(target.token)}</span></li>`}
    <li>${t('verifyFile', { path: '<span class="code">' + esc(scheme + '://' + target.host + path) + '</span>' })}: <span class="code">${esc(target.token)}</span></li></ol>
    <div class="actions"><button class="btn primary" data-act="verify">${t('checkNow')}</button></div>
    ${staff() ? `<div class="staffbox" style="grid-template-columns:1fr auto"><input type="text" id="fvnote" placeholder="${esc(t('forceHolder'))}"><button class="btn" data-act="fverify">${t('confirm')}</button></div>` : ''}</div>`;
}

function findingCard(f) {
  const x = ft(f), act = isActive(f);
  const open = state.openF.has(f.id) ? ' open' : '';
  const st = f.status;
  const stLabel = st === 'requested' ? t('requested') : t(st);
  let btns = '';
  if (!staff()) {
    if (st === 'open') btns = `<button class="btn primary small" data-act="request" data-id="${f.id}" data-v="1">${t('reqFix')}</button><button class="btn small ghost" data-act="accept" data-id="${f.id}" data-v="1">${t('accept')}</button>`;
    else if (st === 'requested') btns = `<button class="btn small ghost" data-act="request" data-id="${f.id}" data-v="0">${t('cancelReq')}</button>`;
    else if (st === 'accepted') btns = `<button class="btn small ghost" data-act="accept" data-id="${f.id}" data-v="0">${t('reopen')}</button>`;
  }
  const ai = f.ai && f.ai[state.lang];
  const aiBtn = (state.meta && state.meta.ai || ai) ? `<button class="btn small" data-act="explain" data-id="${f.id}">${t('explainAI')}</button>` : '';
  const aiBox = ai ? `<div class="ai"><b>${t('aiTitle')}</b>${esc(String(ai).trim().replace(/\n{2,}/g, '\n')).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')}</div>` : '';
  const thread = (f.comments || []).map(c => `<div class="msg ${esc(c.role)}"><span class="by">${esc(c.by)}</span><span class="role">${t(c.role + 'Role')}</span><span class="at">${when(c.at)}</span><div>${esc(c.text)}</div></div>`).join('');
  const staffBox = staff() ? `<div class="staffbox"><select name="status" aria-label="${t('status')}">${['open', 'requested', 'in_progress', 'fixed', 'verified', 'accepted'].map(v => `<option value="${v}" ${v === st ? 'selected' : ''}>${v === 'requested' ? t('requested') : t(v)}</option>`).join('')}</select>
      <input type="text" name="note" placeholder="${esc(t('note'))}"><button class="btn primary small" data-act="status" data-id="${f.id}">${t('save')}</button></div>` : '';
  return `<details class="f ${esc(f.severity)}${act ? '' : ' inactive'}" id="f-${esc(f.id)}" data-fid="${esc(f.id)}"${open}>
    <summary><span class="sevtag ${esc(f.severity)}">${t(f.severity)}</span><h3>${esc(x.title)}</h3><span class="pill ${esc(st)}">${esc(stLabel)}</span></summary>
    <div class="fbody"><p>${esc(x.plain)}</p>
      ${x.fix ? `<div class="fix"><b>${t('howFix')}</b>${esc(x.fix)}</div>` : ''}
      <div class="ev">${t('evidence')}: ${esc(f.evidence)}</div>${aiBox}
      <div class="frow">${btns}${aiBtn}</div>${staffBox}
      <div class="thread">${thread ? `<div>${thread}</div>` : ''}
      <div class="cform"><input type="text" name="comment" placeholder="${esc(t('writeComment'))}" maxlength="2000"><button class="btn small" data-act="comment" data-id="${f.id}">${t('send')}</button></div></div>
    </div></details>`;
}

function checklistCard(target) {
  const cl = target.checklist || [];
  if (!cl.length) return '';
  const done = cl.filter(c => c.done).length, cat = state.meta ? state.meta.checklist : {};
  return `<h2 class="sec">${t('checklistTitle')} <small>${done}/${cl.length}</small></h2><div class="card"><p style="color:var(--muted);margin:0 0 8px">${t('checklistP')}</p>
    <div class="bar"><span style="width:${Math.round(done / cl.length * 100)}%"></span></div>
    <ul class="cl">${cl.map(c => { const l = cat[c.key] || {}; return `<li><input type="checkbox" data-act="check" data-key="${esc(c.key)}" ${c.done ? 'checked' : ''} ${staff() ? '' : 'disabled'} aria-label="${esc(l[state.lang] || c.key)}"><div><div>${esc(l[state.lang] || c.key)}</div>${c.done ? `<div class="note">${esc(c.by || '')} · ${when(c.at)}${c.note ? ' — ' + esc(c.note) : ''}</div>` : ''}</div></li>`; }).join('')}</ul></div>`;
}

function demoCard(target) {
  if (!(state.meta && state.meta.demo && target && target.host === '127.0.0.1:8081')) return '';
  return `<h2 class="sec">${t('demoTitle')}</h2><div class="card"><p class="demo-p">${t('demoP')}</p><div class="actions"><button class="btn primary" data-act="demo" data-v="fix">${t('demoFix')}</button><button class="btn" data-act="demo" data-v="break">${t('demoBreak')}</button></div></div>`;
}

function staffTools() {
  return `<h2 class="sec">${t('addManual')}</h2><form class="card" data-form="manual">
    <label for="m-sev">${t('severity')}</label><select id="m-sev" name="severity">${SEV.slice(0, 4).map(s => `<option value="${s}" ${s === 'medium' ? 'selected' : ''}>${t(s)}</option>`).join('')}</select>
    <label for="m-t">${t('mTitle')}</label><input id="m-t" type="text" name="title" required maxlength="200">
    <label for="m-p">${t('mPlain')}</label><textarea id="m-p" name="plain" maxlength="2000"></textarea>
    <label for="m-f">${t('mFix')}</label><textarea id="m-f" name="fix" maxlength="2000"></textarea>
    <div class="actions"><button class="btn primary" type="submit">${t('add')}</button></div></form>`;
}

/* ---------- scan watching ---------- */
function stopWatch() { clearInterval(state.poll); state.poll = null; state.watching = null; }
function watchScan(id) {
  stopWatch(); state.watching = id;
  state.poll = setInterval(async () => {
    try {
      const sc = await api('GET', '/api/scans/' + encodeURIComponent(id));
      const el = $('#term'); if (el) { el.innerHTML = termHtml(sc, sc.status === 'running'); el.scrollTop = el.scrollHeight; }
      if (sc.status !== 'running') {
        stopWatch(); toast(sc.status === 'done' ? t('scanDone') : t('scanFail') + (sc.error ? ': ' + sc.error : ''), sc.status !== 'done');
        if (state.tid) await showTarget(state.tid, true);
      }
    } catch { stopWatch(); }
  }, 1200);
}

/* ---------- staff pages ---------- */
async function showQueue() {
  const q = await api('GET', '/api/staff/queue');
  const rows = q.items.map(i => { const x = ft(i); return `<tr class="clk" data-go="${esc(i.targetId)}" data-focus="${esc(i.findingId)}"><td><span class="sevtag ${esc(i.severity)}">${t(i.severity)}</span></td><td>${esc(x.title)}${i.manual ? ' <span class="pill">manual</span>' : ''}</td><td>${esc(i.org)}</td><td><span class="code">${esc(i.host)}</span></td><td><span class="pill ${esc(i.status)}">${i.status === 'requested' ? t('requested') : t(i.status)}</span></td><td>${when(i.updated)}</td></tr>`; }).join('');
  const table = q.items.length ? `<div class="card"><table><thead><tr><th></th><th>${t('problem')}</th><th>${t('customer')}</th><th>${t('site')}</th><th>${t('status')}</th><th>${t('updated')}</th></tr></thead><tbody>${rows}</tbody></table></div>`
    : `<div class="card empty"><h3>${t('qEmpty')}</h3><p>${t('qEmptyP')}</p></div>`;
  const pend = q.pending.length ? `<h2 class="sec">${t('pendingTitle')} <small>${q.pending.length}</small></h2><div class="card"><table><tbody>${q.pending.map(p => `<tr class="clk" data-go="${esc(p.targetId)}"><td>${esc(p.org)}</td><td><span class="code">${esc(p.host)}</span></td></tr>`).join('')}</tbody></table></div>` : '';
  $('#app').innerHTML = shell(`<div class="page-h"><div><h1>${t('qTitle')}</h1><p>${t('qSub')}</p></div></div>
    <div class="stats"><div class="stat"><b>${q.orgs}</b><span>${t('stCustomers')}</span></div><div class="stat"><b>${q.targets}</b><span>${t('stSites')}</span></div><div class="stat"><b>${q.items.length}</b><span>${t('stQueue')}</span></div><div class="stat"><b>${q.pending.length}</b><span>${t('stPending')}</span></div></div>${table}${pend}`, '#/queue');
}
async function showAll() {
  const list = await api('GET', '/api/targets');
  $('#app').innerHTML = shell(`<div class="page-h"><div><h1>${t('allCust')}</h1></div></div><div class="card"><table><thead><tr><th>${t('customer')}</th><th>${t('site')}</th><th>${t('grade')}</th><th>${t('openCol')}</th><th>${t('requested')}</th><th>${t('manualReview')}</th></tr></thead><tbody>
    ${list.map(s => `<tr class="clk" data-go="${esc(s.id)}"><td>${esc(s.org)}<div style="color:var(--muted);font-size:12px">${t(s.sector)}</div></td><td><span class="code">${esc(s.host)}</span>${s.verified ? '' : ' <span class="pill warn">' + t('notVerified') + '</span>'}</td><td>${s.scanned ? esc(s.grade) + ' · ' + s.score : '–'}</td><td>${Object.values(s.counts || {}).reduce((a, b) => a + b, 0)}</td><td>${s.requested}</td><td>${s.checkDone}/${s.checkTotal}</td></tr>`).join('')}</tbody></table></div>`, '#/all');
}
async function showAudit() {
  const a = await api('GET', '/api/staff/audit');
  $('#app').innerHTML = shell(`<div class="page-h"><div><h1>${t('audit')}</h1></div></div><div class="card"><table><thead><tr><th>${t('when')}</th><th>${t('who')}</th><th>${t('action')}</th><th>${t('details')}</th></tr></thead><tbody>
    ${a.map(e => `<tr><td>${when(e.at)}</td><td>${esc(e.actor)}</td><td><span class="code">${esc(e.action)}</span></td><td>${esc(e.detail)}</td></tr>`).join('')}</tbody></table></div>`, '#/audit');
}

/* ---------- routing ---------- */
const render = guard(async () => {
  const rm = (location.hash || '').match(/^#\/reset\/([0-9a-f]+)$/);
  if (rm) { stopWatch(); authTab = 'reset'; renderAuth(); return; }
  if (authTab === 'reset') authTab = 'login';
  if (!state.me) { stopWatch(); renderAuth(); return; }
  const h = location.hash || '#/';
  const m = h.match(/^#\/t\/(.+)$/);
  if (m) return showTarget(decodeURIComponent(m[1]));
  stopWatch(); state.tid = null;
  if (staff()) {
    if (h === '#/all') return showAll();
    if (h === '#/audit') return showAudit();
    return showQueue();
  }
  return showHome();
});

/* ---------- events ---------- */
document.addEventListener('toggle', e => {
  const d = e.target; if (d.dataset && d.dataset.fid) d.open ? state.openF.add(d.dataset.fid) : state.openF.delete(d.dataset.fid);
}, true);

document.addEventListener('click', guard(async e => {
  const go = e.target.closest('[data-go]');
  if (go && !e.target.closest('a,button')) { state.focus = go.dataset.focus || null; if (state.focus) state.openF.add(state.focus); location.hash = '#/t/' + go.dataset.go; return; }
  const el = e.target.closest('[data-act]'); if (!el) return;
  const act = el.dataset.act, id = el.dataset.id, card = el.closest('.f');
  switch (act) {
    case 'lang': state.lang = el.dataset.v; try { localStorage.setItem('crimson.lang', state.lang); } catch { } document.documentElement.lang = state.lang; return render();
    case 'tab': authTab = el.dataset.v; return renderAuth();
    case 'logout': await api('POST', '/api/auth/logout'); state.me = null; authTab = 'login'; location.hash = '#/'; return render();
    case 'scan': {
      const deep = !!($('#deepchk') && $('#deepchk').checked);
      await api('POST', `/api/targets/${state.tid}/scan`, { deep }); return showTarget(state.tid, true);
    }
    case 'verify': { const r = await api('POST', `/api/targets/${state.tid}/verify`); toast(r.verified ? t('verifyOk') : t('verifyFail'), !r.verified); return showTarget(state.tid, true); }
    case 'fverify': { await api('POST', `/api/targets/${state.tid}/force-verify`, { note: $('#fvnote').value }); toast(t('verifyOk')); return showTarget(state.tid, true); }
    case 'demo': { await api('POST', '/api/demo/' + el.dataset.v); toast(t('demoDone')); return; }
    case 'reqall': { const r = await api('POST', `/api/targets/${state.tid}/request-all`); toast(t('fixesRequested', { n: r.requested })); return showTarget(state.tid, true); }
    case 'request': await api('POST', `/api/findings/${id}/request`, { requested: el.dataset.v === '1' }); if (el.dataset.v === '1') toast(t('reqSent')); return showTarget(state.tid, true);
    case 'accept': await api('POST', `/api/findings/${id}/accept`, { accept: el.dataset.v === '1' }); return showTarget(state.tid, true);
    case 'comment': { const inp = card.querySelector('[name=comment]'); if (!inp.value.trim()) return; await api('POST', `/api/findings/${id}/comment`, { text: inp.value }); return showTarget(state.tid, true); }
    case 'status': await api('POST', `/api/findings/${id}/status`, { status: card.querySelector('[name=status]').value, note: card.querySelector('[name=note]').value }); toast(t('done')); return showTarget(state.tid, true);
    case 'explain': {
      el.disabled = true; el.textContent = t('thinking');
      try { const r = await api('POST', `/api/findings/${id}/explain`, { lang: state.lang }); const f = state.data.findings.find(x => x.id === id); f.ai = Object.assign(f.ai || {}, { [state.lang]: r.text }); renderTarget(); }
      catch (err) { el.disabled = false; el.textContent = t('explainAI'); throw err; }
      return;
    }
  }
}));

document.addEventListener('change', guard(async e => {
  const el = e.target.closest('[data-act=check]'); if (!el) return;
  await api('POST', `/api/targets/${state.tid}/checklist/${encodeURIComponent(el.dataset.key)}`, { done: el.checked });
  return showTarget(state.tid, true);
}));

document.addEventListener('submit', guard(async e => {
  const form = e.target.closest('form[data-form]'); if (!form) return;
  e.preventDefault();
  const v = Object.fromEntries(new FormData(form).entries());
  switch (form.dataset.form) {
    case 'login': case 'register':
      try { const r = await api('POST', '/api/auth/' + form.dataset.form, v); state.me = r.user; location.hash = '#/'; return render(); }
      catch (err) { $('#autherr').textContent = err.message; return; }
    case 'forgot': {
      const msg = $('#autherr');
      try { await api('POST', '/api/auth/forgot', { email: v.email, lang: state.lang }); msg.className = 'ok'; msg.textContent = t('forgotSent'); form.querySelector('button[type=submit]').disabled = true; }
      catch (err) { msg.className = 'err'; msg.textContent = err.message; }
      return;
    }
    case 'reset': {
      const m = location.hash.match(/^#\/reset\/([0-9a-f]+)$/);
      try { await api('POST', '/api/auth/reset', { token: m ? m[1] : '', password: v.password }); authTab = 'login'; location.hash = '#/'; toast(t('resetDone')); }
      catch (err) { $('#autherr').textContent = err.message; }
      return;
    }
    case 'addtarget': { const r = await api('POST', '/api/targets', { host: v.host }); location.hash = '#/t/' + r.id; return; }
    case 'manual': await api('POST', `/api/targets/${state.tid}/manual`, v); toast(t('done')); return showTarget(state.tid, true);
  }
}));

window.addEventListener('hashchange', render);

(async function init() {
  document.documentElement.lang = state.lang;
  try { state.meta = await api('GET', '/api/meta'); } catch { }
  try { const r = await api('GET', '/api/me'); state.me = r.user; } catch { }
  render();
})();
