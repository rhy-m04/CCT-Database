/**
 * LAS COMMAND PORTAL — Cloudflare Pages Function (API backend)
 * -------------------------------------------------------------
 * Drop-in replacement for the Apps Script "CodeCCT.gs" server. Same rank
 * table, same eligibility rules, same event/incident visibility rules —
 * just backed by Cloudflare D1 (SQL) instead of a Google Sheet, and
 * Cloudflare KV instead of CacheService for session storage.
 *
 * DEPLOYMENT (see README.md for full steps):
 *   1. wrangler d1 create las-portal-db      -> put the id in wrangler.toml
 *   2. wrangler d1 execute las-portal-db --file=schema.sql
 *   3. wrangler kv namespace create SESSIONS -> put the id in wrangler.toml
 *   4. Push this repo to GitHub, connect it to a Cloudflare Pages project.
 *
 * Bindings expected (set in wrangler.toml or the Pages dashboard):
 *   env.DB        - D1 database binding
 *   env.SESSIONS  - KV namespace binding
 *
 * The frontend calls this as a single JSON-RPC style endpoint:
 *   POST /api/rpc   { "method": "login", "args": ["bob", "hunter2"] }
 * See index.html's google.script.run shim for how that's wired up.
 */

// ---------- CONFIG (mirrors CodeCCT.gs) ----------

const MAIN_GROUP_ID = 860308753;          // UK London Ambulance Serv-ce
const CRITICAL_CARE_GROUP_ID = 637235433; // LAS Critical Care Team
const OMBUDSMAN_GROUP_ID = 882881950;     // LAS Ombudsman — independent track
const EMAIL_DOMAIN = 'las.wuk.sg';
const SESSION_TTL_SECONDS = 6 * 60 * 60; // 6 hours

const RANKS = [
  { id: 'jrp',  label: 'Junior Paramedic', tier: 'Probationary Servicemen',              level: 1, match: ['junior paramedic'] },
  { id: 'para', label: 'Paramedic',        tier: 'Probationary Servicemen',              level: 1, match: ['paramedic'] },
  { id: 'sp',   label: 'Specialist Paramedic', tier: 'Servicemen',                       level: 2, match: ['specialist paramedic'] },
  { id: 'advp', label: 'Adv. Paramedic',   tier: 'Supervisory',                          level: 3, match: ['advanced paramedic', 'adv. paramedic', 'adv paramedic'] },
  { id: 'cons', label: 'Consultant',       tier: 'Supervisory',                          level: 3, match: ['consultant'] },
  { id: 'tm',   label: 'TM',               tier: 'Bronze (Division Command)',            level: 4, match: ['team manager', ' tm', 'tm '], reportLevel: 1 },
  { id: 'om',   label: 'OM',               tier: 'Bronze (Division Command)',            level: 4, match: ['operations manager', ' om', 'om '], reportLevel: 2 },
  { id: 'gm',   label: 'GM',               tier: 'Silver (Division Leadership)',         level: 5, match: ['general manager', ' gm', 'gm '], reportLevel: 3 },
  { id: 'ad',   label: 'AD',               tier: 'Silver (Division Leadership)',         level: 5, match: ['assistant director', ' ad', 'ad '], note: 'Division Lead', reportLevel: 4 },
  { id: 'dir',  label: 'DIR',              tier: 'Gold (Admin / Service Oversight)',     level: 6, match: ['director', ' dir'], note: 'Gold Staff', reportLevel: 5 },
  { id: 'dce',  label: 'DCE',              tier: 'Gold (Admin / Service Oversight)',     level: 6, match: ['deputy chief executive', 'dce'], reportLevel: 5 },
  { id: 'ceo',  label: 'CEO',              tier: 'Gold (Admin / Service Oversight)',     level: 6, match: ['chief executive officer', 'ceo'], reportLevel: 5 },
  { id: 'dev',  label: 'Dev',              tier: 'Project Management (Admin)',           level: 7, match: ['developer', ' dev'], reportLevel: 5 },
  { id: 'lead', label: 'Lead',             tier: 'Project Management (Admin)',           level: 7, match: ['lead'], reportLevel: 5 },
  { id: 'omb_inv',  label: 'OMB Investigator', tier: 'Ombudsman — Investigator (Bronze Command)',      level: 4, match: [], isOMB: true },
  { id: 'omb_lead', label: 'OMB Leadership',   tier: 'Ombudsman — Leadership (Silver Command, Audit)', level: 5, match: [], isOMB: true }
];

const TABS = [
  { id: 'modules',      label: 'Module Logging',              minLevel: 3, note: 'SV+' },
  { id: 'incidents',    label: 'Incident Report Logging',     minLevel: 3, note: 'SV+' },
  { id: 'events',       label: 'Event Logging',                minLevel: 3, note: 'SV+' },
  { id: 'quota',        label: 'Quota Tracker',                minLevel: 2, note: 'Servicemen+' },
  { id: 'academy',      label: 'Academy Tracker',              minLevel: 1, note: 'All — view differs by rank' },
  { id: 'myDiscipline', label: 'My Discipline',                minLevel: 1, note: 'All — your own record only' },
  { id: 'weekly',       label: 'Weekly Reports',               minLevel: 4, note: 'Manager+, levels apply' },
  { id: 'activityDisc', label: 'Activity Disciplinary Dashboard', minLevel: 4, note: 'Manager+ / OMB Investigator+' },
  { id: 'internalDisc', label: 'Internal Disciplinary Dashboard', minLevel: 5, note: 'Silver Command+ / OMB Leadership' },
  { id: 'audit',        label: 'Audit Division',               minLevel: 5, note: 'Silver Command+ / OMB Leadership' }
];

const OMB_TAB_WHITELIST = ['myDiscipline', 'activityDisc', 'internalDisc', 'audit'];

const EVENT_TYPES = [
  'CCT Academy Training',
  'HEMS Qualification Course',
  'MIRU Academy Training',
  'Division Deployment',
  'Joint Deployment'
];

function findRankById(id) {
  return RANKS.find(function (r) { return r.id === id; }) || null;
}

function visibleTabsFor(user) {
  return TABS.filter(function (t) {
    if (user.rankLevel < t.minLevel) return false;
    if (user.isOMB && OMB_TAB_WHITELIST.indexOf(t.id) === -1) return false;
    return true;
  }).map(function (t) { return t.id; });
}

// ---------- PASSWORD HASHING (Web Crypto, replaces Utilities.computeDigest) ----------

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const data = enc.encode(salt + password);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

// ---------- ROBLOX API ----------

async function robloxGetUserId(username) {
  const resp = await fetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: true })
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  if (!data.data || data.data.length === 0) return null;
  return data.data[0]; // { id, name, displayName }
}

async function robloxGetGroupRoles(userId) {
  const resp = await fetch('https://groups.roblox.com/v1/users/' + userId + '/groups/roles');
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.data || [];
}

function mapRoleNameToRank(roleName) {
  const name = ' ' + roleName.toLowerCase() + ' ';
  let best = null;
  RANKS.forEach(function (rank) {
    for (let j = 0; j < rank.match.length; j++) {
      if (name.indexOf(rank.match[j]) !== -1) {
        if (!best || rank.level > best.level) best = rank;
        break;
      }
    }
  });
  return best;
}

function mapOmbRoleNameToRank(roleName) {
  const name = ' ' + roleName.toLowerCase() + ' ';
  if (name.indexOf('chief') !== -1 || name.indexOf('executive') !== -1) return findRankById('omb_lead');
  if (name.indexOf('investigator') !== -1) return findRankById('omb_inv');
  return null;
}

async function checkRobloxEligibility(username) {
  username = (username || '').trim();
  if (!username) return { eligible: false, reason: 'Enter a Roblox username.' };

  const userInfo = await robloxGetUserId(username);
  if (!userInfo) return { eligible: false, reason: 'No Roblox account found with that username.' };

  const groupRoles = await robloxGetGroupRoles(userInfo.id);

  const ombEntry = groupRoles.find(function (g) { return g.group.id === OMBUDSMAN_GROUP_ID; });
  if (ombEntry) {
    return {
      eligible: true,
      robloxUserId: userInfo.id,
      robloxUsername: userInfo.name,
      roleNameInGame: ombEntry.role.name,
      rank: mapOmbRoleNameToRank(ombEntry.role.name)
    };
  }

  const mainEntry = groupRoles.find(function (g) { return g.group.id === MAIN_GROUP_ID; });
  const ccEntry = groupRoles.find(function (g) { return g.group.id === CRITICAL_CARE_GROUP_ID; });

  if (!mainEntry) {
    return { eligible: false, reason: 'Not a member of the UK London Ambulance Serv-ce group, or the LAS Ombudsman group.', robloxUserId: userInfo.id };
  }
  if (!ccEntry) {
    return { eligible: false, reason: 'Not a member of the LAS Critical Care Team group (required for eligibility).', robloxUserId: userInfo.id };
  }

  const rank = mapRoleNameToRank(ccEntry.role.name);
  return {
    eligible: true,
    robloxUserId: userInfo.id,
    robloxUsername: userInfo.name,
    roleNameInGame: ccEntry.role.name,
    rank: rank
  };
}

// ---------- D1 HELPERS ----------

async function findUserRow(db, username) {
  const uname = username.toLowerCase();
  const row = await db.prepare('SELECT * FROM Users WHERE lower(Username) = ?').bind(uname).first();
  return row || null;
}

function rowToUser(row) {
  const rank = findRankById(row.RankId);
  return {
    username: row.Username,
    email: row.Email,
    rankId: row.RankId,
    rankLabel: row.RankLabel,
    rankTier: row.RankTier,
    rankLevel: Number(row.RankLevel),
    reportLevel: rank && rank.reportLevel ? rank.reportLevel : 0,
    isOMB: !!(rank && rank.isOMB),
    robloxUserId: row.RobloxUserId
  };
}

function safeParseJson(text, fallback) {
  try { return JSON.parse(text); } catch (e) { return fallback; }
}

function eventRowToObject(row) {
  return {
    id: row.Id, createdAt: row.CreatedAt, loggedBy: row.LoggedBy, timeOfEvent: row.TimeOfEvent,
    host: row.Host, coHost: row.CoHost, eventType: row.EventType,
    attendees: safeParseJson(row.AttendeesJson, []), performance: safeParseJson(row.PerformanceJson, []),
    whatWentWell: row.WhatWentWell, improvementAreas: row.ImprovementAreas, incidentLogId: row.IncidentLogId,
    additionalComments: row.AdditionalComments, reviewedBy: row.ReviewedBy, reviewedAt: row.ReviewedAt
  };
}

function incidentRowToObject(row) {
  return {
    id: row.Id, createdAt: row.CreatedAt, loggedBy: row.LoggedBy, timeOfEvent: row.TimeOfEvent,
    host: row.Host, coHosts: row.CoHosts, membersInvolved: row.MembersInvolved,
    incidentDescription: row.IncidentDescription, evidenceLinks: row.EvidenceLinks,
    reviewingManager: row.ReviewingManager, actionTakenNotes: row.ActionTakenNotes, reviewedAt: row.ReviewedAt
  };
}

function canSeeEventLog(user, record) {
  if (user.rankLevel >= 4) return true;
  if (user.rankLevel === 3) {
    const uname = user.username.toLowerCase();
    if ((record.host || '').toLowerCase() === uname) return true;
    if ((record.coHost || '').toLowerCase() === uname) return true;
    return false;
  }
  return false;
}

// ---------- SESSIONS (KV, replaces CacheService) ----------

async function sessionUser(env, token) {
  if (!token) return null;
  const cached = await env.SESSIONS.get('session_' + token);
  if (!cached) return null;
  return JSON.parse(cached);
}

// ---------- RPC METHODS ----------

const methods = {
  async checkRobloxEligibility(env, [username]) {
    return checkRobloxEligibility(username);
  },

  async getRankOptions(env) {
    return RANKS.map(function (r) {
      return { id: r.id, label: r.label, tier: r.tier, note: r.note || '' };
    });
  },

  async getEventTypes(env) {
    return EVENT_TYPES;
  },

  async createAccount(env, [username, password, overrideRankId]) {
    username = (username || '').trim();
    if (!username || !password) return { success: false, message: 'Username and password are required.' };
    if (password.length < 8) return { success: false, message: 'Password must be at least 8 characters.' };
    if (await findUserRow(env.DB, username)) {
      return { success: false, message: 'An account already exists for that Roblox username.' };
    }

    const check = await checkRobloxEligibility(username);
    if (!check.eligible) return { success: false, message: check.reason };

    let rank = check.rank;
    if (!rank && overrideRankId) rank = findRankById(overrideRankId);
    if (!rank) {
      return {
        success: false,
        message: 'Could not automatically match the in-game role "' + check.roleNameInGame +
          '" to a rank. Ask a Manager to create this account and manually select a rank.',
        needsManualRank: true,
        roleNameInGame: check.roleNameInGame
      };
    }

    const salt = crypto.randomUUID();
    const hash = await hashPassword(password, salt);
    const email = username + '@' + EMAIL_DOMAIN;

    await env.DB.prepare(
      'INSERT INTO Users (Username, Email, PasswordHash, Salt, RankId, RankLabel, RankTier, RankLevel, RobloxUserId, CreatedAt) VALUES (?,?,?,?,?,?,?,?,?,?)'
    ).bind(username, email, hash, salt, rank.id, rank.label, rank.tier, rank.level, String(check.robloxUserId), new Date().toISOString()).run();

    return { success: true, message: 'Account created for ' + username + ' (' + rank.label + ').' };
  },

  async login(env, [loginId, password]) {
    const username = (loginId || '').split('@')[0].trim();
    const row = await findUserRow(env.DB, username);
    if (!row) return { success: false, message: 'No account found for that username.' };

    const attemptHash = await hashPassword(password, row.Salt);
    if (attemptHash !== row.PasswordHash) return { success: false, message: 'Incorrect password.' };

    const user = rowToUser(row);
    const token = crypto.randomUUID();
    await env.SESSIONS.put('session_' + token, JSON.stringify(user), { expirationTtl: SESSION_TTL_SECONDS });

    return { success: true, token: token, user: user, tabs: visibleTabsFor(user) };
  },

  async getSession(env, [token]) {
    const user = await sessionUser(env, token);
    if (!user) return null;
    return { user: user, tabs: visibleTabsFor(user) };
  },

  async logout(env, [token]) {
    if (token) await env.SESSIONS.delete('session_' + token);
    return { success: true };
  },

  async submitEventLog(env, [token, data]) {
    const user = await sessionUser(env, token);
    if (!user) return { success: false, message: 'Your session has expired — please sign in again.' };
    if (user.rankLevel < 3) return { success: false, message: 'You do not have permission to log events.' };
    if (!data || !(data.host || '').trim() || !(data.eventType || '').trim()) {
      return { success: false, message: 'Host and event type are required.' };
    }

    const id = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO EventLogs (Id, CreatedAt, LoggedBy, TimeOfEvent, Host, CoHost, EventType, AttendeesJson, PerformanceJson, WhatWentWell, ImprovementAreas, IncidentLogId, AdditionalComments, ReviewedBy, ReviewedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(
      id, new Date().toISOString(), user.username,
      data.timeOfEvent || '', data.host.trim(), (data.coHost || '').trim(), data.eventType,
      JSON.stringify(data.attendees || []), JSON.stringify(data.performance || []),
      data.whatWentWell || '', data.improvementAreas || '',
      (data.incidentLogId || '').trim(), data.additionalComments || '', '', ''
    ).run();

    return { success: true, message: 'Event log submitted.', id: id };
  },

  async listEventLogs(env, [token]) {
    const user = await sessionUser(env, token);
    if (!user) return { success: false, message: 'Your session has expired — please sign in again.', logs: [] };

    const { results } = await env.DB.prepare('SELECT * FROM EventLogs').all();
    const logs = results
      .map(eventRowToObject)
      .filter(function (record) { return canSeeEventLog(user, record); })
      .sort(function (a, b) { return new Date(b.createdAt) - new Date(a.createdAt); });

    return { success: true, logs: logs };
  },

  async reviewEventLog(env, [token, id]) {
    const user = await sessionUser(env, token);
    if (!user || user.rankLevel < 4) return { success: false, message: 'Manager+ only.' };

    const res = await env.DB.prepare(
      'UPDATE EventLogs SET ReviewedBy = ?, ReviewedAt = ? WHERE Id = ?'
    ).bind(user.username, new Date().toISOString(), id).run();

    if (!res.meta || res.meta.changes === 0) return { success: false, message: 'Event log not found.' };
    return { success: true };
  },

  async submitIncidentReport(env, [token, data]) {
    const user = await sessionUser(env, token);
    if (!user) return { success: false, message: 'Your session has expired — please sign in again.' };
    if (user.rankLevel < 3) return { success: false, message: 'You do not have permission to log incidents.' };
    if (!data || !(data.host || '').trim() || !(data.incidentDescription || '').trim()) {
      return { success: false, message: 'Host and incident description are required.' };
    }

    const id = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO IncidentReports (Id, CreatedAt, LoggedBy, TimeOfEvent, Host, CoHosts, MembersInvolved, IncidentDescription, EvidenceLinks, ReviewingManager, ActionTakenNotes, ReviewedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(
      id, new Date().toISOString(), user.username,
      data.timeOfEvent || '', data.host.trim(), (data.coHosts || '').trim(),
      (data.membersInvolved || '').trim(), data.incidentDescription.trim(), (data.evidenceLinks || '').trim(),
      '', '', ''
    ).run();

    return { success: true, message: 'Incident report submitted.', id: id };
  },

  async listIncidentReports(env, [token]) {
    const user = await sessionUser(env, token);
    if (!user) return { success: false, message: 'Your session has expired — please sign in again.', logs: [] };

    const { results } = await env.DB.prepare('SELECT * FROM IncidentReports').all();
    const logs = results
      .map(incidentRowToObject)
      .filter(function (record) {
        const isOwner = record.loggedBy.toLowerCase() === user.username.toLowerCase();
        return user.rankLevel >= 4 || isOwner;
      })
      .sort(function (a, b) { return new Date(b.createdAt) - new Date(a.createdAt); });

    return { success: true, logs: logs };
  },

  async reviewIncidentReport(env, [token, id, notes]) {
    const user = await sessionUser(env, token);
    if (!user || user.rankLevel < 4) return { success: false, message: 'Manager+ only.' };

    const res = await env.DB.prepare(
      'UPDATE IncidentReports SET ReviewingManager = ?, ActionTakenNotes = ?, ReviewedAt = ? WHERE Id = ?'
    ).bind(user.username, notes || '', new Date().toISOString(), id).run();

    if (!res.meta || res.meta.changes === 0) return { success: false, message: 'Incident report not found.' };
    return { success: true };
  }
};

// ---------- HTTP ENTRY POINT ----------

export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ success: false, message: 'Invalid JSON body.' }, 400);
  }

  const { method, args } = body || {};
  const fn = methods[method];
  if (!fn) return jsonResponse({ success: false, message: 'Unknown method: ' + method }, 400);

  try {
    const result = await fn(env, Array.isArray(args) ? args : []);
    return jsonResponse(result, 200);
  } catch (err) {
    return jsonResponse({ success: false, message: 'Server error: ' + (err && err.message ? err.message : String(err)) }, 500);
  }
}

export async function onRequestGet() {
  return jsonResponse({ success: false, message: 'POST only.' }, 405);
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' }
  });
}
