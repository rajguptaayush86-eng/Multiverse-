import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import multer from "multer";
import { v4 as uuid } from "uuid";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET =
  process.env.JWT_SECRET || "dev-only-change-this-secret";

const COOKIE_SECURE =
  process.env.COOKIE_SECURE === "true";

const MAX_UPLOAD_MB =
  Number(process.env.MAX_UPLOAD_MB || 50);

const app = express();

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(cookieParser());

const dataDir =
  path.join(__dirname, "data");

const uploadDir =
  path.join(__dirname, "uploads");

fs.mkdirSync(dataDir, {
  recursive: true
});

fs.mkdirSync(uploadDir, {
  recursive: true
});

const db =
  new Database(
    path.join(
      dataDir,
      "multiverse.db"
    )
  );

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS universes(
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'internal',
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  lore TEXT NOT NULL DEFAULT '',
  creator TEXT NOT NULL DEFAULT '',
  template TEXT NOT NULL DEFAULT 'Blank Universe',
  visibility TEXT NOT NULL DEFAULT 'public',
  password_hash TEXT,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(owner_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS
idx_universes_visibility
ON universes(visibility);

CREATE TABLE IF NOT EXISTS versions(
  id TEXT PRIMARY KEY,
  universe_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log(
  id TEXT PRIMARY KEY,
  universe_id TEXT,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS media(
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`);

const upload =
  multer({
    storage:
      multer.diskStorage({
        destination:
          uploadDir,

        filename:
          (req, file, cb) => {
            cb(
              null,
              uuid() +
              path
                .extname(
                  file.originalname
                )
                .toLowerCase()
            );
          }
      }),

    limits: {
      fileSize:
        MAX_UPLOAD_MB *
        1024 *
        1024
    },

    fileFilter:
      (req, file, cb) => {

        const allowed =
          /^(image|video|audio)\//
            .test(
              file.mimetype
            );

        cb(
          allowed
            ? null
            : new Error(
                "Only image, video, or audio uploads are allowed"
              ),
          allowed
        );
      }
  });

function now() {
  return new Date().toISOString();
}

function sign(user) {

  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function setAuth(
  res,
  token
) {

  res.cookie(
    "mp_session",
    token,
    {
      httpOnly: true,
      sameSite: "lax",
      secure: COOKIE_SECURE,
      maxAge:
        7 *
        24 *
        60 *
        60 *
        1000,
      path: "/"
    }
  );
}

function auth(
  req,
  res,
  next
) {

  try {

    const token =
      req.cookies.mp_session;

    if (!token) {

      return res
        .status(401)
        .json({
          error:
            "Authentication required"
        });
    }

    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();

  } catch {

    return res
      .status(401)
      .json({
        error:
          "Invalid or expired session"
      });
  }
}

function safeUser(row) {

  return {
    id: row.id,
    email: row.email,
    displayName:
      row.display_name,
    role: row.role,
    createdAt:
      row.created_at
  };
}

function getUniverse(id) {

  const row =
    db.prepare(
      "SELECT * FROM universes WHERE id=?"
    ).get(id);

  if (!row)
    return null;

  return {
    ...JSON.parse(
      row.data_json
    ),

    id: row.id,
    ownerId:
      row.owner_id,
    type: row.type,
    title: row.title,
    description:
      row.description,
    lore: row.lore,
    creator:
      row.creator,
    template:
      row.template,
    visibility:
      row.visibility,
    createdAt:
      row.created_at,
    updatedAt:
      row.updated_at
  };
}

function canView(
  universe,
  user
) {

  if (
    universe.visibility ===
    "public"
  ) {
    return true;
  }

  if (
    universe.ownerId ===
    user?.sub
  ) {
    return true;
  }

  const members =
    Array.isArray(
      universe.members
    )
      ? universe.members
      : [];

  return members.some(
    member =>
      member.id ===
        user?.sub ||
      member.email ===
        user?.email
  );
}

function canEdit(
  universe,
  user
) {

  if (!user)
    return false;

  if (
    universe.ownerId ===
    user.sub
  ) {
    return true;
  }

  const editors =
    Array.isArray(
      universe.editors
    )
      ? universe.editors
      : [];

  return editors.some(
    editor =>
      editor.id ===
        user.sub ||
      editor.email ===
        user.email
  );
}

function audit(
  universeId,
  actorId,
  action,
  meta = {}
) {

  db.prepare(`
    INSERT INTO audit_log(
      id,
      universe_id,
      actor_id,
      action,
      meta_json,
      created_at
    )
    VALUES(?,?,?,?,?,?)
  `).run(
    uuid(),
    universeId,
    actorId,
    action,
    JSON.stringify(meta),
    now()
  );
}

/* HEALTH */

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      ok: true,
      time: now()
    });

  }
);

/* REGISTER */

app.post(
  "/api/auth/register",
  async (req, res) => {

    const {
      email,
      password,
      displayName
    } = req.body || {};

    if (
      !email ||
      !password ||
      password.length < 8
    ) {

      return res
        .status(400)
        .json({
          error:
            "Email and password (8+ characters) are required"
        });
    }

    const normalized =
      email
        .toLowerCase()
        .trim();

    if (
      db.prepare(
        "SELECT id FROM users WHERE email=?"
      ).get(normalized)
    ) {

      return res
        .status(409)
        .json({
          error:
            "Account already exists"
        });
    }

    const user = {

      id: uuid(),

      email: normalized,

      passwordHash:
        await bcrypt.hash(
          password,
          12
        ),

      displayName:
        (
          displayName ||
          normalized.split("@")[0]
        ).slice(
          0,
          80
        ),

      role: "user",

      createdAt: now()
    };

    db.prepare(`
      INSERT INTO users(
        id,
        email,
        password_hash,
        display_name,
        role,
        created_at
      )
      VALUES(?,?,?,?,?,?)
    `).run(
      user.id,
      user.email,
      user.passwordHash,
      user.displayName,
      user.role,
      user.createdAt
    );

    setAuth(
      res,
      sign(user)
    );

    res
      .status(201)
      .json({
        user: {
          id: user.id,
          email: user.email,
          displayName:
            user.displayName,
          role: user.role
        }
      });

  }
);

/* LOGIN */

app.post(
  "/api/auth/login",
  async (req, res) => {

    const {
      email,
      password
    } = req.body || {};

    const row =
      db.prepare(
        "SELECT * FROM users WHERE email=?"
      ).get(
        String(
          email || ""
        )
          .toLowerCase()
          .trim()
      );

    if (
      !row ||
      !(await bcrypt.compare(
        password || "",
        row.password_hash
      ))
    ) {

      return res
        .status(401)
        .json({
          error:
            "Invalid email or password"
        });
    }

    setAuth(
      res,
      sign(row)
    );

    res.json({
      user:
        safeUser(row)
    });

  }
);

/* LOGOUT */

app.post(
  "/api/auth/logout",
  (req, res) => {

    res.clearCookie(
      "mp_session",
      {
        httpOnly: true,
        sameSite: "lax",
        secure:
          COOKIE_SECURE,
        path: "/"
      }
    );

    res.json({
      ok: true
    });

  }
);

/* CURRENT USER */

app.get(
  "/api/auth/me",
  (req, res) => {

    try {

      const token =
        req.cookies.mp_session;

      if (!token) {

        return res.json({
          user: null
        });
      }

      const payload =
        jwt.verify(
          token,
          JWT_SECRET
        );

      const row =
        db.prepare(
          "SELECT * FROM users WHERE id=?"
        ).get(
          payload.sub
        );

      res.json({
        user:
          row
            ? safeUser(row)
            : null
      });

    } catch {

      res.json({
        user: null
      });

    }

  }
);

/* PUBLIC UNIVERSES */

app.get(
  "/api/universes",
  (req, res) => {

    const rows =
      db.prepare(`
        SELECT *
        FROM universes
        WHERE visibility='public'
        ORDER BY updated_at DESC
      `).all();

    res.json({
      universes:
        rows.map(
          row =>
            getUniverse(
              row.id
            )
        )
    });

  }
);

/* SINGLE UNIVERSE */

app.get(
  "/api/universes/:id",
  (req, res) => {

    const universe =
      getUniverse(
        req.params.id
      );

    if (!universe) {

      return res
        .status(404)
        .json({
          error:
            "Universe not found"
        });
    }

    let user = null;

    try {

      const token =
        req.cookies.mp_session;

      if (token) {

        user =
          jwt.verify(
            token,
            JWT_SECRET
          );
      }

    } catch {}

    if (
      !canView(
        universe,
        user
      )
    ) {

      return res
        .status(403)
        .json({
          error:
            "Access denied"
        });
    }

    res.json({
      universe
    });

  }
);

/* CREATE UNIVERSE */

app.post(
  "/api/universes",
  auth,
  (req, res) => {

    const body =
      req.body || {};

    const id =
      uuid();

    const timestamp =
      now();

    const visibilityOptions = [
      "public",
      "unlisted",
      "private",
      "password",
      "invite"
    ];

    const universe = {

      ...body,

      id,

      ownerId:
        req.user.sub,

      type:
        body.type ===
        "external"
          ? "external"
          : "internal",

      title:
        String(
          body.title ||
          "New Universe"
        ).slice(
          0,
          160
        ),

      description:
        String(
          body.description ||
          ""
        ),

      lore:
        String(
          body.lore ||
          ""
        ),

      creator:
        String(
          body.creator ||
          ""
        ),

      template:
        String(
          body.template ||
          "Blank Universe"
        ),

      visibility:
        visibilityOptions.includes(
          body.visibility
        )
          ? body.visibility
          : "public",

      createdAt:
        timestamp,

      updatedAt:
        timestamp
    };

    db.prepare(`
      INSERT INTO universes(
        id,
        owner_id,
        type,
        title,
        description,
        lore,
        creator,
        template,
        visibility,
        password_hash,
        data_json,
        created_at,
        updated_at
      )
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      id,
      req.user.sub,
      universe.type,
      universe.title,
      universe.description,
      universe.lore,
      universe.creator,
      universe.template,
      universe.visibility,
      null,
      JSON.stringify(
        universe
      ),
      timestamp,
      timestamp
    );

    audit(
      id,
      req.user.sub,
      "Universe created"
    );

    res
      .status(201)
      .json({
        universe:
          getUniverse(id)
      });

  }
);

/* UPDATE */

app.put(
  "/api/universes/:id",
  auth,
  (req, res) => {

    const universe =
      getUniverse(
        req.params.id
      );

    if (!universe) {

      return res
        .status(404)
        .json({
          error:
            "Universe not found"
        });
    }

    if (
      !canEdit(
        universe,
        req.user
      )
    ) {

      return res
        .status(403)
        .json({
          error:
            "Editor access required"
        });
    }

    const updated = {

      ...universe,

      ...req.body,

      id:
        universe.id,

      ownerId:
        universe.ownerId,

      updatedAt:
        now()
    };

    db.prepare(`
      UPDATE universes
      SET
        type=?,
        title=?,
        description=?,
        lore=?,
        creator=?,
        template=?,
        visibility=?,
        data_json=?,
        updated_at=?
      WHERE id=?
    `).run(
      updated.type,
      updated.title,
      updated.description,
      updated.lore,
      updated.creator,
      updated.template,
      updated.visibility,
      JSON.stringify(
        updated
      ),
      updated.updatedAt,
      universe.id
    );

    audit(
      universe.id,
      req.user.sub,
      "Universe updated"
    );

    res.json({
      universe:
        getUniverse(
          universe.id
        )
    });

  }
);

/* DELETE */

app.delete(
  "/api/universes/:id",
  auth,
  (req, res) => {

    const universe =
      getUniverse(
        req.params.id
      );

    if (!universe) {

      return res
        .status(404)
        .json({
          error:
            "Universe not found"
        });
    }

    if (
      universe.ownerId !==
      req.user.sub
    ) {

      return res
        .status(403)
        .json({
          error:
            "Owner access required"
        });
    }

    db.prepare(
      "DELETE FROM universes WHERE id=?"
    ).run(
      universe.id
    );

    audit(
      universe.id,
      req.user.sub,
      "Universe deleted"
    );

    res.json({
      ok: true
    });

  }
);

/* VERSION */

app.post(
  "/api/universes/:id/versions",
  auth,
  (req, res) => {

    const universe =
      getUniverse(
        req.params.id
      );

    if (
      !universe ||
      !canEdit(
        universe,
        req.user
      )
    ) {

      return res
        .status(403)
        .json({
          error:
            "Editor access required"
        });
    }

    const versionId =
      uuid();

    db.prepare(`
      INSERT INTO versions(
        id,
        universe_id,
        actor_id,
        snapshot_json,
        created_at
      )
      VALUES(?,?,?,?,?)
    `).run(
      versionId,
      universe.id,
      req.user.sub,
      JSON.stringify(
        universe
      ),
      now()
    );

    audit(
      universe.id,
      req.user.sub,
      "Version snapshot created",
      {
        versionId
      }
    );

    res
      .status(201)
      .json({
        id:
          versionId
      });

  }
);

/* VERSION LIST */

app.get(
  "/api/universes/:id/versions",
  auth,
  (req, res) => {

    const universe =
      getUniverse(
        req.params.id
      );

    if (
      !universe ||
      !canView(
        universe,
        req.user
      )
    ) {

      return res
        .status(403)
        .json({
          error:
            "Access denied"
        });
    }

    const versions =
      db.prepare(`
        SELECT
          id,
          actor_id,
          created_at
        FROM versions
        WHERE universe_id=?
        ORDER BY created_at DESC
      `).all(
        universe.id
      );

    res.json({
      versions
    });

  }
);

/* AUDIT */

app.get(
  "/api/universes/:id/audit",
  auth,
  (req, res) => {

    const universe =
      getUniverse(
        req.params.id
      );

    if (
      !universe ||
      universe.ownerId !==
        req.user.sub
    ) {

      return res
        .status(403)
        .json({
          error:
            "Owner access required"
        });
    }

    const auditRows =
      db.prepare(`
        SELECT *
        FROM audit_log
        WHERE universe_id=?
        ORDER BY created_at DESC
        LIMIT 200
      `).all(
        universe.id
      );

    res.json({
      audit:
        auditRows
    });

  }
);

/* MEDIA UPLOAD */

app.post(
  "/api/media",
  auth,
  upload.single("file"),
  (req, res) => {

    if (!req.file) {

      return res
        .status(400)
        .json({
          error:
            "No media file"
        });
    }

    const id =
      uuid();

    db.prepare(`
      INSERT INTO media(
        id,
        owner_id,
        filename,
        mime,
        size,
        path,
        created_at
      )
      VALUES(?,?,?,?,?,?,?)
    `).run(
      id,
      req.user.sub,
      req.file.originalname,
      req.file.mimetype,
      req.file.size,
      req.file.filename,
      now()
    );

    res
      .status(201)
      .json({
        id,
        url:
          `/uploads/${req.file.filename}`,
        mime:
          req.file.mimetype,
        size:
          req.file.size
      });

  }
);

app.use(
  "/uploads",
  express.static(
    uploadDir,
    {
      maxAge: "7d",
      index: false
    }
  )
);

/* USER STATE */

app.get(
  "/api/state",
  auth,
  (req, res) => {

    const rows =
      db.prepare(`
        SELECT id
        FROM universes
        WHERE owner_id=?
        ORDER BY updated_at DESC
      `).all(
        req.user.sub
      );

    res.json({
      universes:
        rows.map(
          row =>
            getUniverse(
              row.id
            )
        )
    });

  }
);

/* PORTAL BOOTSTRAP */

app.get(
  "/api/portal/bootstrap",
  async (req, res) => {

    let user = null;

    try {

      const token =
        req.cookies.mp_session;

      if (token) {

        const payload =
          jwt.verify(
            token,
            JWT_SECRET
          );

        const row =
          db.prepare(
            "SELECT * FROM users WHERE id=?"
          ).get(
            payload.sub
          );

        if (row)
          user =
            safeUser(row);
      }

    } catch {}

    const publicRows =
      db.prepare(`
        SELECT id
        FROM universes
        WHERE visibility='public'
        ORDER BY updated_at DESC
      `).all();

    const publicUniverses =
      publicRows.map(
        row =>
          getUniverse(
            row.id
          )
      );

    const mine =
      user
        ? db.prepare(`
            SELECT id
            FROM universes
            WHERE owner_id=?
            ORDER BY updated_at DESC
          `).all(
            user.id
          ).map(
            row =>
              getUniverse(
                row.id
              )
          )
        : [];

    const map =
      new Map();

    [
      ...publicUniverses,
      ...mine
    ].forEach(
      universe =>
        map.set(
          universe.id,
          universe
        )
    );

    res.json({
      user,
      universes:
        [...map.values()]
    });

  }
);

/* STATIC FRONTEND */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
)
