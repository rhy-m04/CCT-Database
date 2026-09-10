-- LAS Command Portal — D1 schema
-- Replaces the "Users", "EventLogs" and "IncidentReports" tabs from the
-- original Google Sheet. Apply with:
--   wrangler d1 execute las-portal-db --file=schema.sql --remote

CREATE TABLE IF NOT EXISTS Users (
  Username      TEXT PRIMARY KEY,
  Email         TEXT NOT NULL,
  PasswordHash  TEXT NOT NULL,
  Salt          TEXT NOT NULL,
  RankId        TEXT NOT NULL,
  RankLabel     TEXT NOT NULL,
  RankTier      TEXT NOT NULL,
  RankLevel     INTEGER NOT NULL,
  RobloxUserId  TEXT,
  CreatedAt     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS EventLogs (
  Id                 TEXT PRIMARY KEY,
  CreatedAt          TEXT NOT NULL,
  LoggedBy           TEXT NOT NULL,
  TimeOfEvent        TEXT,
  Host               TEXT NOT NULL,
  CoHost             TEXT,
  EventType          TEXT NOT NULL,
  AttendeesJson      TEXT,
  PerformanceJson    TEXT,
  WhatWentWell       TEXT,
  ImprovementAreas   TEXT,
  IncidentLogId      TEXT,
  AdditionalComments TEXT,
  ReviewedBy         TEXT,
  ReviewedAt         TEXT
);

CREATE TABLE IF NOT EXISTS IncidentReports (
  Id                   TEXT PRIMARY KEY,
  CreatedAt            TEXT NOT NULL,
  LoggedBy             TEXT NOT NULL,
  TimeOfEvent          TEXT,
  Host                 TEXT NOT NULL,
  CoHosts              TEXT,
  MembersInvolved      TEXT,
  IncidentDescription  TEXT NOT NULL,
  EvidenceLinks        TEXT,
  ReviewingManager     TEXT,
  ActionTakenNotes     TEXT,
  ReviewedAt           TEXT
);

CREATE INDEX IF NOT EXISTS idx_eventlogs_createdat ON EventLogs (CreatedAt);
CREATE INDEX IF NOT EXISTS idx_incidents_createdat ON IncidentReports (CreatedAt);
