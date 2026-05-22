const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 4001;

const config = {
  discordClientId:     process.env.DISCORD_CLIENT_ID,
  discordClientSecret: process.env.DISCORD_CLIENT_SECRET,
  jwtSecret:           process.env.JWT_SECRET,
  baseUrl:             process.env.BASE_URL || 'https://playlist.droidlab.org',
  dbPath:              process.env.DB_PATH  || '/app/data/db.sqlite',
  youtubeApiKey:       process.env.YOUTUBE_API_KEY,
  spotifyClientId:     process.env.SPOTIFY_CLIENT_ID,
  spotifyClientSecret: process.env.SPOTIFY_CLIENT_SECRET,
};

const DISCORD_REDIRECT = `${config.baseUrl}/auth/callback`;
const SPOTIFY_REDIRECT  = `${config.baseUrl}/auth/spotify/callback`;
const SPOTIFY_SCOPES    = 'playlist-read-private playlist-read-collaborative';

const db = new Database(config.dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    discord_id   TEXT PRIMARY KEY,
    username     TEXT NOT NULL,
    global_name  TEXT,
    avatar       TEXT,
    created_at   INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS playlists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    TEXT NOT NULL REFERENCES users(discord_id),
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    private     INTEGER DEFAULT 1,
    created_at  INTEGER DEFAULT (unixepoch()),
    UNIQUE(owner_id, name)
  );
  CREATE TABLE IF NOT EXISTS tracks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    playlist_id INTEGER NOT NULL REFERENCES playlists(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    artist      TEXT DEFAULT '',
    url         TEXT NOT NULL,
    source      TEXT NOT NULL CHECK(source IN ('youtube','spotify')),
    duration    INTEGER DEFAULT 0,
    thumbnail   TEXT DEFAULT '',
    added_at    INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS play_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id  TEXT NOT NULL REFERENCES users(discord_id),
    playlist_id INTEGER NOT NULL REFERENCES playlists(id),
    track_count INTEGER DEFAULT 0,
    played_at   INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS spotify_accounts (
    discord_id     TEXT PRIMARY KEY REFERENCES users(discord_id),
    spotify_id     TEXT NOT NULL,
    display_name   TEXT,
    access_token   TEXT NOT NULL,
    refresh_token  TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    connected_at   INTEGER DEFAULT (unixepoch())
  );
`);

const stmts = {
  upsertUser:           db.prepare(`INSERT INTO users (discord_id, username, global_name, avatar) VALUES (@discord_id, @username, @global_name, @avatar) ON CONFLICT(discord_id) DO UPDATE SET username=excluded.username, global_name=excluded.global_name, avatar=excluded.avatar`),
  getUser:              db.prepare(`SELECT * FROM users WHERE discord_id = ?`),
  getUserPlaylists:     db.prepare(`SELECT * FROM playlists WHERE owner_id = ? ORDER BY created_at DESC`),
  getPlaylist:          db.prepare(`SELECT * FROM playlists WHERE id = ?`),
  getPlaylistByName:    db.prepare(`SELECT * FROM playlists WHERE owner_id = ? AND name = ? COLLATE NOCASE`),
  createPlaylist:       db.prepare(`INSERT INTO playlists (owner_id, name, description, private) VALUES (@owner_id, @name, @description, @private)`),
  deletePlaylist:       db.prepare(`DELETE FROM playlists WHERE id = ? AND owner_id = ?`),
  updatePlaylist:       db.prepare(`UPDATE playlists SET name=@name, description=@description, private=@private WHERE id=@id AND owner_id=@owner_id`),
  getPlaylistTracks:    db.prepare(`SELECT * FROM tracks WHERE playlist_id = ? ORDER BY added_at ASC`),
  addTrack:             db.prepare(`INSERT INTO tracks (playlist_id, title, artist, url, source, duration, thumbnail) VALUES (@playlist_id, @title, @artist, @url, @source, @duration, @thumbnail)`),
  deleteTrack:          db.prepare(`DELETE FROM tracks WHERE id = ? AND playlist_id IN (SELECT id FROM playlists WHERE owner_id = ?)`),
  trackCount:           db.prepare(`SELECT COUNT(*) as count FROM tracks WHERE playlist_id = ?`),
  totalTracks:          db.prepare(`SELECT COUNT(*) as count FROM tracks WHERE playlist_id IN (SELECT id FROM playlists WHERE owner_id = ?)`),
  totalPlays:           db.prepare(`SELECT COALESCE(SUM(track_count),0) as count FROM play_events WHERE discord_id = ?`),
  logPlay:              db.prepare(`INSERT INTO play_events (discord_id, playlist_id, track_count) VALUES (@discord_id, @playlist_id, @track_count)`),
  getSpotifyAccount:    db.prepare(`SELECT * FROM spotify_accounts WHERE discord_id = ?`),
  upsertSpotifyAccount: db.prepare(`INSERT INTO spotify_accounts (discord_id, spotify_id, display_name, access_token, refresh_token, expires_at) VALUES (@discord_id, @spotify_id, @display_name, @access_token, @refresh_token, @expires_at) ON CONFLICT(discord_id) DO UPDATE SET spotify_id=excluded.spotify_id, display_name=excluded.display_name, access_token=excluded.access_token, refresh_token=excluded.refresh_token, expires_at=excluded.expires_at`),
  deleteSpotifyAccount: db.prepare(`DELETE FROM spotify_accounts WHERE discord_id = ?`),
};

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

function requireAuth(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token) return res.status(401).json({ error: 'Unauthorised' });
  try {
    req.user = jwt.verify(token, config.jwtSecret);
    next();
  } catch {
    res.clearCookie('auth_token');
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function ownPlaylist(req, res) {
  const playlist = stmts.getPlaylist.get(req.params.id);
  if (!playlist) { res.status(404).json({ error: 'Playlist not found' }); return null; }
  if (playlist.owner_id !== req.user.discord_id) { res.status(403).json({ error: 'Forbidden' }); return null; }
  return playlist;
}

async function getValidSpotifyToken(discordId) {
  const account = stmts.getSpotifyAccount.get(discordId);
  if (!account) return null;

  if (Date.now() < account.expires_at - 60000) {
    return account.access_token;
  }

  // Refresh the token
  const creds = Buffer.from(`${config.spotifyClientId}:${config.spotifyClientSecret}`).toString('base64');
  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: account.refresh_token }),
  });
  const data = await res.json();
  if (!data.access_token) return null;

  stmts.upsertSpotifyAccount.run({
    discord_id:    discordId,
    spotify_id:    account.spotify_id,
    display_name:  account.display_name,
    access_token:  data.access_token,
    refresh_token: data.refresh_token || account.refresh_token,
    expires_at:    Date.now() + (data.expires_in * 1000),
  });

  return data.access_token;
}

// ── Discord Auth ──────────────────────────────────────────────────────────────
app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id:     config.discordClientId,
    redirect_uri:  DISCORD_REDIRECT,
    response_type: 'code',
    scope:         'identify',
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?error=oauth_denied');
  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     config.discordClientId,
        client_secret: config.discordClientSecret,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  DISCORD_REDIRECT,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token');
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const discordUser = await userRes.json();
    stmts.upsertUser.run({
      discord_id:  discordUser.id,
      username:    discordUser.username,
      global_name: discordUser.global_name || discordUser.username,
      avatar:      discordUser.avatar,
    });
    const token = jwt.sign({
      discord_id:  discordUser.id,
      username:    discordUser.username,
      global_name: discordUser.global_name || discordUser.username,
      avatar:      discordUser.avatar,
    }, config.jwtSecret, { expiresIn: '30d' });
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge:   30 * 24 * 60 * 60 * 1000,
    });
    res.redirect('/dashboard');
  } catch (err) {
    console.error('OAuth error:', err);
    res.redirect('/?error=oauth_failed');
  }
});

app.get('/auth/me', requireAuth, (req, res) => {
  const user = stmts.getUser.get(req.user.discord_id);
  res.json(user || req.user);
});

app.post('/auth/logout', requireAuth, (req, res) => {
  res.clearCookie('auth_token');
  res.json({ ok: true });
});

// ── Spotify Auth ──────────────────────────────────────────────────────────────
app.get('/auth/spotify', requireAuth, (req, res) => {
  const params = new URLSearchParams({
    client_id:     config.spotifyClientId,
    redirect_uri:  SPOTIFY_REDIRECT,
    response_type: 'code',
    scope:         SPOTIFY_SCOPES,
    state:         req.user.discord_id,
  });
  res.redirect(`https://accounts.spotify.com/authorize?${params}`);
});

app.get('/auth/spotify/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code || !state) return res.redirect('/profile?error=spotify_denied');

  try {
    const creds = Buffer.from(`${config.spotifyClientId}:${config.spotifyClientSecret}`).toString('base64');
    const tokenRes = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:   'authorization_code',
        code,
        redirect_uri: SPOTIFY_REDIRECT,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token');

    const profileRes = await fetch('https://api.spotify.com/v1/me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const spotifyProfile = await profileRes.json();

    stmts.upsertSpotifyAccount.run({
      discord_id:    state,
      spotify_id:    spotifyProfile.id,
      display_name:  spotifyProfile.display_name || spotifyProfile.id,
      access_token:  tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_at:    Date.now() + (tokenData.expires_in * 1000),
    });

    res.redirect('/profile?spotify=connected');
  } catch (err) {
    console.error('Spotify OAuth error:', err);
    res.redirect('/profile?error=spotify_failed');
  }
});

app.delete('/auth/spotify', requireAuth, (req, res) => {
  stmts.deleteSpotifyAccount.run(req.user.discord_id);
  res.json({ ok: true });
});

// ── Profile ───────────────────────────────────────────────────────────────────
app.get('/api/profile', requireAuth, (req, res) => {
  const user = stmts.getUser.get(req.user.discord_id);
  const playlists = stmts.getUserPlaylists.all(req.user.discord_id);
  const totalTracks = stmts.totalTracks.get(req.user.discord_id).count;
  const totalPlays = stmts.totalPlays.get(req.user.discord_id).count;
  const spotify = stmts.getSpotifyAccount.get(req.user.discord_id);
  res.json({
    user,
    stats: { playlists: playlists.length, tracks: totalTracks, plays: totalPlays },
    spotify: spotify ? { connected: true, display_name: spotify.display_name, spotify_id: spotify.spotify_id } : { connected: false },
  });
});

// ── Spotify Playlists (for import) ────────────────────────────────────────────
app.get('/api/spotify/playlists', requireAuth, async (req, res) => {
  const token = await getValidSpotifyToken(req.user.discord_id);
  if (!token) return res.status(401).json({ error: 'Spotify not connected' });

  const playlists = [];
  let url = 'https://api.spotify.com/v1/me/playlists?limit=50';

  while (url) {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await r.json();
    for (const p of (data.items || [])) {
      playlists.push({
        id:          p.id,
        name:        p.name,
        track_count: p.tracks?.total ?? 0,
        image:       p.images?.[0]?.url || '',
        owner:       p.owner.display_name,
      });
    }
    url = data.next || null;
  }

  res.json(playlists);
});

// ── Spotify Import ────────────────────────────────────────────────────────────
app.post('/api/spotify/import', requireAuth, async (req, res) => {
  const { playlist_ids } = req.body;
  if (!playlist_ids?.length) return res.status(400).json({ error: 'No playlists selected' });

  const token = await getValidSpotifyToken(req.user.discord_id);
  if (!token) return res.status(401).json({ error: 'Spotify not connected' });

  const results = [];

  for (const spotifyPlaylistId of playlist_ids) {
    try {
      // Get playlist info
      const infoRes = await fetch(`https://api.spotify.com/v1/playlists/${spotifyPlaylistId}?fields=name,tracks.total`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const info = await infoRes.json();

      // Create playlist in DB
      let playlistId;
      try {
        const result = stmts.createPlaylist.run({
          owner_id:    req.user.discord_id,
          name:        info.name,
          description: '',
          private:     1,
        });
        playlistId = result.lastInsertRowid;
      } catch {
        // Already exists — get existing
        const existing = stmts.getPlaylistByName.get(req.user.discord_id, info.name);
        if (!existing) { results.push({ name: info.name, error: 'Failed to create' }); continue; }
        playlistId = existing.id;
      }

      // Fetch all tracks
      let tracksUrl = `https://api.spotify.com/v1/playlists/${spotifyPlaylistId}/tracks?limit=100&fields=next,items(track(name,duration_ms,artists,album(images)))`;
      let imported = 0;

      while (tracksUrl) {
        const tracksRes = await fetch(tracksUrl, { headers: { Authorization: `Bearer ${token}` } });
        const tracksData = await tracksRes.json();

        for (const item of (tracksData.items || [])) {
          const t = item.track;
          if (!t) continue;
          stmts.addTrack.run({
            playlist_id: playlistId,
            title:       t.name,
            artist:      t.artists?.map(a => a.name).join(', ') || '',
            url:         `ytsearch:${t.artists?.[0]?.name || ''} ${t.name}`,
            source:      'spotify',
            duration:    Math.round((t.duration_ms || 0) / 1000),
            thumbnail:   t.album?.images?.[0]?.url || '',
          });
          imported++;
        }

        tracksUrl = tracksData.next || null;
      }

      results.push({ name: info.name, imported });
    } catch (err) {
      results.push({ name: spotifyPlaylistId, error: String(err) });
    }
  }

  res.json({ results });
});

// ── Playlist Routes ───────────────────────────────────────────────────────────
app.get('/api/playlists', requireAuth, (req, res) => {
  const playlists = stmts.getUserPlaylists.all(req.user.discord_id);
  res.json(playlists.map(p => ({ ...p, track_count: stmts.trackCount.get(p.id).count })));
});

app.post('/api/playlists', requireAuth, (req, res) => {
  const { name, description = '', private: priv = true } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  try {
    const result = stmts.createPlaylist.run({ owner_id: req.user.discord_id, name: name.trim(), description: description.trim(), private: priv ? 1 : 0 });
    res.json({ id: result.lastInsertRowid, name: name.trim() });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Playlist name already exists' });
    res.status(500).json({ error: 'Failed to create playlist' });
  }
});

app.patch('/api/playlists/:id', requireAuth, (req, res) => {
  const playlist = ownPlaylist(req, res);
  if (!playlist) return;
  const { name = playlist.name, description = playlist.description, private: priv = playlist.private } = req.body;
  stmts.updatePlaylist.run({ name, description, private: priv ? 1 : 0, id: playlist.id, owner_id: req.user.discord_id });
  res.json({ ok: true });
});

app.delete('/api/playlists/:id', requireAuth, (req, res) => {
  const playlist = ownPlaylist(req, res);
  if (!playlist) return;
  stmts.deletePlaylist.run(playlist.id, req.user.discord_id);
  res.json({ ok: true });
});

app.get('/api/playlists/:id/tracks', requireAuth, (req, res) => {
  const playlist = stmts.getPlaylist.get(req.params.id);
  if (!playlist) return res.status(404).json({ error: 'Not found' });
  if (playlist.owner_id !== req.user.discord_id && playlist.private) return res.status(403).json({ error: 'Private playlist' });
  res.json(stmts.getPlaylistTracks.all(playlist.id));
});

app.post('/api/playlists/:id/tracks', requireAuth, (req, res) => {
  const playlist = ownPlaylist(req, res);
  if (!playlist) return;
  const { title, artist = '', url, source, duration = 0, thumbnail = '' } = req.body;
  if (!title || !url || !source) return res.status(400).json({ error: 'title, url, source required' });
  const result = stmts.addTrack.run({ playlist_id: playlist.id, title, artist, url, source, duration, thumbnail });
  res.json({ id: result.lastInsertRowid });
});

app.delete('/api/tracks/:id', requireAuth, (req, res) => {
  const changes = stmts.deleteTrack.run(req.params.id, req.user.discord_id);
  if (changes.changes === 0) return res.status(404).json({ error: 'Track not found or not yours' });
  res.json({ ok: true });
});

// ── Search ────────────────────────────────────────────────────────────────────
app.get('/api/search', requireAuth, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'q required' });

  const spotifyTrackMatch = q.match(/spotify\.com\/track\/([A-Za-z0-9]+)/);
  if (spotifyTrackMatch) {
    try { return res.json({ results: [await spotifyTrackInfo(spotifyTrackMatch[1])] }); }
    catch { return res.status(500).json({ error: 'Spotify lookup failed' }); }
  }

  const spotifyPlaylistMatch = q.match(/spotify\.com\/playlist\/([A-Za-z0-9]+)/);
  if (spotifyPlaylistMatch) {
    try { return res.json({ results: await spotifyPlaylistTracks(spotifyPlaylistMatch[1]), bulk: true }); }
    catch { return res.status(500).json({ error: 'Spotify playlist lookup failed' }); }
  }

  const ytIdMatch = q.match(/(?:v=|youtu\.be\/)([A-Za-z0-9_-]{11})/);
  if (ytIdMatch) {
    try { return res.json({ results: [await youtubeVideoInfo(ytIdMatch[1])] }); }
    catch { return res.status(500).json({ error: 'YouTube lookup failed' }); }
  }

  try {
    res.json({ results: await youtubeSearch(q) });
  } catch {
    res.status(500).json({ error: 'YouTube search failed' });
  }
});

// ── Bot Routes ────────────────────────────────────────────────────────────────
app.get('/api/bot/user/:discordId/playlists', async (req, res) => {
  const playlists = stmts.getUserPlaylists.all(req.params.discordId);
  const pub = playlists.filter(p => p.private === 0).map(p => ({ ...p, track_count: stmts.trackCount.get(p.id).count }));
  if (pub.length === 0) return res.status(404).json({ error: 'No public playlists' });
  res.json(pub);
});

app.get('/api/bot/playlist/:name', async (req, res) => {
  const { user } = req.query;
  if (!user) return res.status(400).json({ error: 'user param required' });
  const playlist = stmts.getPlaylistByName.get(user, req.params.name);
  if (!playlist) return res.status(404).json({ error: 'Playlist not found' });
  if (playlist.private) return res.status(403).json({ error: 'Playlist is private' });
  const tracks = stmts.getPlaylistTracks.all(playlist.id);
  stmts.logPlay.run({ discord_id: user, playlist_id: playlist.id, track_count: tracks.length });
  res.json({ name: playlist.name, tracks: tracks.map(t => ({ title: t.title, artist: t.artist, url: t.url, source: t.source, duration: t.duration, thumbnail: t.thumbnail })) });
});

// ── YouTube helpers ───────────────────────────────────────────────────────────
async function youtubeSearch(query) {
  const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&maxResults=6&q=${encodeURIComponent(query)}&key=${config.youtubeApiKey}`;
  const res = await fetch(url);
  const data = await res.json();
  if (!data.items) throw new Error(data.error?.message || 'YT search failed');
  const ids = data.items.map(i => i.id.videoId).join(',');
  const details = await youtubeVideoDetails(ids);
  return data.items.map((item, i) => ({
    title: item.snippet.title, artist: item.snippet.channelTitle,
    url: `https://www.youtube.com/watch?v=${item.id.videoId}`,
    source: 'youtube', thumbnail: item.snippet.thumbnails?.medium?.url || '', duration: details[i] || 0,
  }));
}

async function youtubeVideoInfo(videoId) {
  const url = `https://www.googleapis.com/youtube/v3/videos?part=snippet,contentDetails&id=${videoId}&key=${config.youtubeApiKey}`;
  const res = await fetch(url);
  const data = await res.json();
  const item = data.items?.[0];
  if (!item) throw new Error('Video not found');
  return {
    title: item.snippet.title, artist: item.snippet.channelTitle,
    url: `https://www.youtube.com/watch?v=${videoId}`,
    source: 'youtube', thumbnail: item.snippet.thumbnails?.medium?.url || '',
    duration: parseDuration(item.contentDetails?.duration || ''),
  };
}

async function youtubeVideoDetails(ids) {
  const url = `https://www.googleapis.com/youtube/v3/videos?part=contentDetails&id=${ids}&key=${config.youtubeApiKey}`;
  const res = await fetch(url);
  const data = await res.json();
  return (data.items || []).map(i => parseDuration(i.contentDetails?.duration || ''));
}

function parseDuration(iso) {
  const m = iso.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!m) return 0;
  return (parseInt(m[1] || 0) * 3600) + (parseInt(m[2] || 0) * 60) + parseInt(m[3] || 0);
}

// ── Spotify client credentials helpers ───────────────────────────────────────
let spotifyToken = null;
let spotifyTokenExpiry = 0;

async function getSpotifyToken() {
  if (spotifyToken && Date.now() < spotifyTokenExpiry) return spotifyToken;
  const creds = Buffer.from(`${config.spotifyClientId}:${config.spotifyClientSecret}`).toString('base64');
  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  });
  const data = await res.json();
  spotifyToken = data.access_token;
  spotifyTokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  return spotifyToken;
}

async function spotifyTrackInfo(trackId) {
  const token = await getSpotifyToken();
  const res = await fetch(`https://api.spotify.com/v1/tracks/${trackId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const t = await res.json();
  return {
    title: t.name, artist: t.artists?.map(a => a.name).join(', ') || '',
    url: `ytsearch:${t.artists?.[0]?.name || ''} ${t.name}`,
    source: 'spotify', thumbnail: t.album?.images?.[0]?.url || '',
    duration: Math.round((t.duration_ms || 0) / 1000),
  };
}

async function spotifyPlaylistTracks(playlistId) {
  const token = await getSpotifyToken();
  const tracks = [];
  let url = `https://api.spotify.com/v1/playlists/${playlistId}/tracks?limit=100&fields=next,items(track(id,name,duration_ms,artists,album(images)))`;
  while (url) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    for (const item of (data.items || [])) {
      const t = item.track;
      if (!t) continue;
      tracks.push({
        title: t.name, artist: t.artists?.map(a => a.name).join(', ') || '',
        url: `ytsearch:${t.artists?.[0]?.name || ''} ${t.name}`,
        source: 'spotify', thumbnail: t.album?.images?.[0]?.url || '',
        duration: Math.round((t.duration_ms || 0) / 1000),
      });
    }
    url = data.next || null;
  }
  return tracks;
}

// ── SPA routes ────────────────────────────────────────────────────────────────
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '../public/dashboard.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, '../public/profile.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

app.listen(PORT, () => console.log(`Playlist app running on port ${PORT}`));
