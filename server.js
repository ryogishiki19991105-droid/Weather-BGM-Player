require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const qs = require('querystring');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const REDIRECT_URI =
  process.env.SPOTIFY_REDIRECT_URI || `http://127.0.0.1:${PORT}/callback`;
const FRONTEND_URI =
  process.env.FRONTEND_URI ||
  (() => {
    try {
      const u = new URL(REDIRECT_URI);
      return `${u.protocol}//${u.hostname}:${u.port}`;
    } catch (_) {
      return `http://127.0.0.1:${PORT}`;
    }
  })();

// -------------------- Postgres (for My Playlists) --------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// 起動時にテーブルを自動作成する（psql 不要）
async function initDb() {
  const sql = `
    CREATE TABLE IF NOT EXISTS my_playlists (
      id SERIAL PRIMARY KEY,
      user_spotify_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS my_playlist_tracks (
      id SERIAL PRIMARY KEY,
      playlist_id INTEGER NOT NULL REFERENCES my_playlists(id) ON DELETE CASCADE,
      position INTEGER NOT NULL,
      track_name TEXT NOT NULL,
      artists TEXT,
      spotify_uri TEXT,
      external_url TEXT,
      image_url TEXT
    );
  `;
  try {
    await pool.query(sql);
    console.log('[initDb] tables ready');
  } catch (e) {
    console.error('[initDb] error:', e);
  }
}

/* -------------------- Middlewares -------------------- */
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

function setAuthCookies(res, access_token, expires_in, refresh_token) {
  const maxAge = Math.max(1, parseInt(expires_in || 3600, 10) - 30) * 1000;
  // Render で HTTPS 運用するなら secure: true にしてもOK
  res.cookie('access_token', access_token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge,
  });
  if (refresh_token) {
    res.cookie('refresh_token', refresh_token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 30 * 24 * 3600 * 1000,
    });
  }
}

async function ensureAccessToken(req, res, next) {
  let at = req.cookies.access_token;
  if (at) {
    req.access_token = at;
    return next();
  }
  const refresh = req.cookies.refresh_token;
  if (!refresh) return res.status(401).json({ error: 'not_logged_in' });
  try {
    const rt = await axios.post(
      'https://accounts.spotify.com/api/token',
      qs.stringify({
        grant_type: 'refresh_token',
        refresh_token: refresh,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
      { headers: { 'content-type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, expires_in } = rt.data;
    setAuthCookies(res, access_token, expires_in, null);
    req.access_token = access_token;
    next();
  } catch (e) {
    console.error('ensureAccessToken', e.response?.data || e.message);
    res.status(401).json({ error: 'auth_failed' });
  }
}

// Spotify の /me を呼び出してユーザー情報を取得
async function getSpotifyUser(req) {
  const r = await axios.get('https://api.spotify.com/v1/me', {
    headers: { Authorization: 'Bearer ' + req.access_token },
  });
  return r.data; // { id, display_name, ... }
}

/* -------------------- API: health -------------------- */
app.get('/ping', (req, res) => res.json({ ok: true }));

/* -------------------- API: Spotify OAuth -------------------- */
app.get('/login', (req, res) => {
  const from = req.query.from || 'home';
  const scope = [
    'user-read-email',
    'user-read-private',
    'streaming',
    'user-modify-playback-state',
    'user-read-playback-state',
    'playlist-read-private',
  ].join(' ');

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    scope,
    redirect_uri: REDIRECT_URI,
    state: from,
  });

  res.redirect(
    'https://accounts.spotify.com/authorize?' + params.toString()
  );
});

app.get('/callback', async (req, res) => {
  const code = req.query.code;
  const from = req.query.state || 'home';
  if (!code) return res.status(400).send('Missing code');

  try {
    const tokenRes = await axios.post(
      'https://accounts.spotify.com/api/token',
      qs.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
      { headers: { 'content-type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, expires_in } = tokenRes.data;
    setAuthCookies(res, access_token, expires_in, refresh_token);
    return res.redirect(`${FRONTEND_URI}?from=${encodeURIComponent(from)}`);
  } catch (e) {
    console.error('/callback error', e.response?.data || e.message);
    return res.status(500).send('Auth error');
  }
});

app.get('/token', async (req, res) => {
  let access = req.cookies.access_token;
  const refresh = req.cookies.refresh_token;
  if (access) return res.json({ access_token: access });
  if (!refresh) return res.status(401).json({ error: 'not_logged_in' });

  try {
    const rt = await axios.post(
      'https://accounts.spotify.com/api/token',
      qs.stringify({
        grant_type: 'refresh_token',
        refresh_token: refresh,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
      { headers: { 'content-type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, expires_in } = rt.data;
    setAuthCookies(res, access_token, expires_in, null);
    return res.json({ access_token });
  } catch (e) {
    console.error('refresh error', e.response?.data || e.message);
    return res.status(401).json({ error: 'refresh_failed' });
  }
});

/* -------------------- API: Spotify resources -------------------- */
app.get('/me', ensureAccessToken, async (req, res) => {
  try {
    const r = await axios.get('https://api.spotify.com/v1/me', {
      headers: { Authorization: 'Bearer ' + req.access_token },
    });
    res.json(r.data);
  } catch (e) {
    res
      .status(e.response?.status || 500)
      .json(e.response?.data || { error: 'me_failed' });
  }
});

app.get('/devices', ensureAccessToken, async (req, res) => {
  try {
    const r = await axios.get(
      'https://api.spotify.com/v1/me/player/devices',
      { headers: { Authorization: 'Bearer ' + req.access_token } }
    );
    res.json(r.data);
  } catch (e) {
    res
      .status(e.response?.status || 500)
      .json(e.response?.data || { error: 'devices_failed' });
  }
});

app.put('/transfer', ensureAccessToken, async (req, res) => {
  const device_id = req.body.device_id;
  if (!device_id)
    return res.status(400).json({ error: 'missing device_id' });
  try {
    await axios.put(
      'https://api.spotify.com/v1/me/player',
      { device_ids: [device_id], play: false },
      {
        headers: {
          Authorization: 'Bearer ' + req.access_token,
          'content-type': 'application/json',
        },
      }
    );
    res.json({ ok: true });
  } catch (e) {
    res
      .status(e.response?.status || 500)
      .json(e.response?.data || { error: 'transfer_failed' });
  }
});

app.put('/play', ensureAccessToken, async (req, res) => {
  try {
    await axios.put(
      'https://api.spotify.com/v1/me/player/play',
      req.body,
      {
        headers: {
          Authorization: 'Bearer ' + req.access_token,
          'content-type': 'application/json',
        },
      }
    );
    res.json({ ok: true });
  } catch (e) {
    res
      .status(e.response?.status || 500)
      .json(e.response?.data || { error: 'play_failed' });
  }
});

app.get('/playlists', ensureAccessToken, async (req, res) => {
  try {
    const r = await axios.get(
      'https://api.spotify.com/v1/me/playlists?limit=50',
      { headers: { Authorization: 'Bearer ' + req.access_token } }
    );
    const items = (r.data.items || []).map((p) => ({
      id: p.id,
      name: p.name,
      uri: p.uri,
      tracks_total: p.tracks?.total || 0,
      image: p.images?.[0]?.url || null,
      external_url: p.external_urls?.spotify || null,
      owner: p.owner?.display_name || p.owner?.id || '',
    }));
    res.json({ items });
  } catch (e) {
    res
      .status(e.response?.status || 500)
      .json(e.response?.data || { error: 'playlists_failed' });
  }
});

app.get('/playlist/:id/tracks', ensureAccessToken, async (req, res) => {
  const { id } = req.params;
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 100);
  const fields =
    'items(track(name,uri,external_urls,artists(name),album(images)))';
  try {
    const r = await axios.get(
      `https://api.spotify.com/v1/playlists/${encodeURIComponent(
        id
      )}/tracks?limit=${limit}&fields=${fields}`,
      { headers: { Authorization: 'Bearer ' + req.access_token } }
    );
    const items = (r.data.items || []).map((x) => {
      const t = x.track || {};
      return {
        name: t.name,
        uri: t.uri,
        external_url: t.external_urls?.spotify || null,
        artists: (t.artists || []).map((a) => a.name),
        image: t.album?.images?.[0]?.url || null,
      };
    });
    res.json({ items });
  } catch (e) {
    res
      .status(e.response?.status || 500)
      .json(e.response?.data || { error: 'playlist_tracks_failed' });
  }
});

/* -------------------- API: このサイト専用マイプレイリスト -------------------- */

// 自分のマイプレイリスト一覧
app.get('/my-playlists', ensureAccessToken, async (req, res) => {
  try {
    const me = await getSpotifyUser(req);
    const userSpotifyId = me.id;

    const client = await pool.connect();
    try {
      const plRes = await client.query(
        'SELECT id, name, description, created_at FROM my_playlists WHERE user_spotify_id = $1 ORDER BY created_at DESC',
        [userSpotifyId]
      );

      const playlists = [];
      for (const row of plRes.rows) {
        const trRes = await client.query(
          `SELECT track_name, artists, spotify_uri, external_url, image_url, position
             FROM my_playlist_tracks
            WHERE playlist_id = $1
            ORDER BY position ASC`,
          [row.id]
        );
        playlists.push({
          id: row.id,
          name: row.name,
          description: row.description,
          created_at: row.created_at,
          tracks: trRes.rows.map((t) => ({
            name: t.track_name,
            artists: t.artists,
            uri: t.spotify_uri,
            external_url: t.external_url,
            image: t.image_url,
          })),
        });
      }

      res.json({ items: playlists });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('GET /my-playlists error', e);
    res.status(500).json({ error: 'my_playlists_failed' });
  }
});

// 新しいマイプレイリストを保存
app.post('/my-playlists', ensureAccessToken, async (req, res) => {
  const { name, description, tracks } = req.body;

  if (!name || !Array.isArray(tracks) || tracks.length === 0) {
    return res
      .status(400)
      .json({ error: 'name と tracks は必須です' });
  }

  try {
    const me = await getSpotifyUser(req);
    const userSpotifyId = me.id;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const plRes = await client.query(
        'INSERT INTO my_playlists (user_spotify_id, name, description) VALUES ($1, $2, $3) RETURNING id',
        [userSpotifyId, name, description || '']
      );
      const playlistId = plRes.rows[0].id;

      const insertText = `
        INSERT INTO my_playlist_tracks
          (playlist_id, position, track_name, artists, spotify_uri, external_url, image_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `;

      for (let i = 0; i < tracks.length; i++) {
        const t = tracks[i] || {};
        await client.query(insertText, [
          playlistId,
          i + 1,
          t.name || '',
          Array.isArray(t.artists)
            ? t.artists.join(', ')
            : t.artists || '',
          t.uri || '',
          t.external_url || '',
          t.image || '',
        ]);
      }

      await client.query('COMMIT');

      res.status(201).json({ id: playlistId, name });
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('POST /my-playlists inner error', e);
      res.status(500).json({ error: 'my_playlists_save_failed' });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('POST /my-playlists error', e);
    res.status(500).json({ error: 'my_playlists_failed' });
  }
});

/* -------------------- Static files & SPA -------------------- */
app.use(express.static(path.join(__dirname, 'public')));
// 必要なら SPA fallback を使う
// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, 'public/index.html'));
// });

/* -------------------- Logout -------------------- */
app.get('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.redirect(FRONTEND_URI);
});
app.post('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.json({ ok: true });
});

/* -------------------- Boot -------------------- */
app.listen(PORT, async () => {
  console.log('Server on ' + (FRONTEND_URI || `http://127.0.0.1:${PORT}`));
  await initDb(); // 起動時にPostgresのテーブルをJSだけで準備
});
