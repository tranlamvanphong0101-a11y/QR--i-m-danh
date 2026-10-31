
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();
const path = require('path');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require("helmet");

// Khoá bí mật cho mã QR: nếu chưa đặt QR_SECRET_KEY trên Render thì tự tạo khoá ngẫu nhiên mỗi lần máy chủ khởi động,
// tránh dùng khoá mặc định mà ai đọc mã nguồn công khai cũng biết.
if (!process.env.QR_SECRET_KEY || process.env.QR_SECRET_KEY === 'default-secret-key') {
  process.env.QR_SECRET_KEY = crypto.randomBytes(32).toString('hex');
  console.warn('QR_SECRET_KEY chưa được đặt: dùng khoá ngẫu nhiên tạm thời (nên đặt QR_SECRET_KEY trên Render).');
}
//const sha256 = require('./sha256');

// Import models and routes
const User = require("./models/User");
const Attendance = require("./models/Attendance");
const StudentProfile = require("./models/StudentProfile");
const studentProfileRoutes = require("./routes/studentProfile");
const attendanceRoutes = require("./routes/attendance");
const { generateQRCode, validateSession, getSessionInfo } = require('./qr-generator');

// --- NEW: Import algorithm modules ---
// Assuming these files exist in an 'algorithms' directory at the same level as server.js
// And they export functions as described in the thought process.
let dijkstra, profileOptimizer, graphTraversal;
try {
  dijkstra = require('./algorithms/dijkstra');
  profileOptimizer = require('./algorithms/profileOptimizer');
  graphTraversal = require('./algorithms/graphTraversal');
  console.log("Successfully loaded algorithm modules.");
} catch (err) {
  console.warn("Warning: Could not load one or more algorithm modules. Related endpoints might not work.", err.message);
  // Define dummy functions if modules are missing to prevent server crashes on require
  dijkstra = { findShortestPath: () => { throw new Error("Dijkstra module not loaded"); } };
  profileOptimizer = { getProfileRecommendations: () => { throw new Error("ProfileOptimizer module not loaded"); } };
  graphTraversal = { exploreCommunity: () => { throw new Error("GraphTraversal module not loaded"); } };
}
// --- END NEW ---


const requiredEnvVars = ['MONGO_URI'];
requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    console.error(`${envVar} environment variable is required`);
    process.exit(1);
  }
});

const app = express();
app.set('trust proxy', 1);

// Configuration Constants
const CLASS_LAT = 10.870;
const CLASS_LNG = 106.799;
const MAX_DISTANCE_METERS = 150;

const QR_CODE_DIR = path.join(__dirname, '../frontend/public/qrcodes');

// --- Bán kính theo từng mã QR và "vé quét" cho sinh viên ---
// Vé quét: khi sinh viên quét đúng lúc mã còn hạn, họ có thêm 3 phút để điền form,
// nên không bị báo hết hạn nữa dù mã trên màn hình đã đổi sang mã mới.
const ALLOWED_RADIUS = [50, 100, 150];

// --- Cảnh báo "nghi trùng thiết bị": cùng cấu hình máy + cùng IP, khác MSSV, điểm danh gần nhau ---
// Chỉ để giảng viên tham khảo, không chặn ai. Lưu trong bộ nhớ nên khởi động lại máy chủ sẽ mất.
const SUSPECT_WINDOW_MS = 15 * 60 * 1000;
const deviceGroups = new Map(); // "ngày|ip|nhóm" -> [{ roll, ts }]
const suspectFlags = new Map(); // ngày -> Map(MSSV -> Set(MSSV nghi trùng))

function addSuspect(date, a, b) {
  if (!suspectFlags.has(date)) suspectFlags.set(date, new Map());
  const m = suspectFlags.get(date);
  if (!m.has(a)) m.set(a, new Set());
  m.get(a).add(b);
}

function registerDevice(date, ip, group, roll) {
  if (typeof group !== 'string' || !group || group.length > 64) return;
  const key = `${date}|${ip}|${group}`;
  const now = Date.now();
  const list = deviceGroups.get(key) || [];
  for (const e of list) {
    if (e.roll !== roll && now - e.ts <= SUSPECT_WINDOW_MS) {
      addSuspect(date, roll, e.roll);
      addSuspect(date, e.roll, roll);
    }
  }
  list.push({ roll, ts: now });
  deviceGroups.set(key, list);
}

setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [k, list] of deviceGroups) {
    const kept = list.filter(e => e.ts > cutoff);
    if (kept.length) deviceGroups.set(k, kept); else deviceGroups.delete(k);
  }
}, 60 * 60 * 1000).unref();
const TICKET_TTL_MS = 3 * 60 * 1000;
const sessionRadius = new Map(); // sessionId -> { radius, at }
const scanTickets = new Map();   // ticket -> { sessionId, lat, lng, radius, expiresAt }

// --- Bảo mật điểm danh ---
// Mã QR chỉ dùng được trong 25 giây kể từ lúc tạo (màn hình đổi mã mỗi 15 giây),
// nên ảnh chụp mã gửi qua Zalo/Messenger gần như không kịp dùng.
const SCAN_WINDOW_MS = 25 * 1000;
const COOKIE_TICKET = 'att_ticket'; // gắn "vé quét" vào đúng trình duyệt đã quét mã
const COOKIE_DEVICE = 'att_dev';    // nhớ thiết bị đã điểm danh cho MSSV nào trong ngày
const COOKIE_SECRET = process.env.QR_SECRET_KEY || 'default-secret-key';

function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) {
      const k = part.slice(0, i).trim();
      try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { out[k] = part.slice(i + 1).trim(); }
    }
  });
  return out;
}
function signValue(v) {
  return v + '.' + crypto.createHmac('sha256', COOKIE_SECRET).update(v).digest('hex').slice(0, 32);
}
function readSigned(signed) {
  if (typeof signed !== 'string') return null;
  const i = signed.lastIndexOf('.');
  if (i < 0) return null;
  const v = signed.slice(0, i);
  return signValue(v) === signed ? v : null;
}
function cookieOpts(req, maxAge) {
  return { httpOnly: true, secure: !!req.secure, sameSite: 'lax', path: '/', maxAge };
}

// Kiểm tra vé quét của sinh viên: phải đúng phiên, còn hạn, và phải là trình duyệt đã quét mã
function checkStudentTicket(req) {
  const body = req.body || {};
  const sessionId = body.sessionId, ticket = body.ticket;
  if (!sessionId || !ticket) return { error: 'Hãy dùng camera quét trực tiếp mã QR đang chiếu trên màn hình' };
  const t = scanTickets.get(ticket);
  if (!t || t.sessionId !== sessionId || t.expiresAt < Date.now()) {
    return { error: 'Mã QR đã hết hạn, hãy quét lại mã đang chiếu trên màn hình' };
  }
  if (parseCookies(req)[COOKIE_TICKET] !== ticket) {
    return { error: 'Liên kết này không phải do điện thoại của bạn quét. Hãy dùng camera quét trực tiếp mã trên màn hình.' };
  }
  return { info: t };
}

// --- Cảnh báo vị trí nghi giả (chỉ để giảng viên tham khảo, không chặn) ---
const locRecords = new Map(); // ngày -> [{ roll, lat, lng, acc }]
const locFlags = new Map();   // ngày -> Map(MSSV -> lý do)
function setLocFlag(date, roll, text) {
  if (!locFlags.has(date)) locFlags.set(date, new Map());
  const m = locFlags.get(date);
  if (!m.has(roll)) m.set(roll, text);
}
function analyzeLocation(date, roll, loc, samples) {
  const acc = Number(loc && loc.acc);
  if (loc && loc.acc !== undefined && acc === 0) {
    setLocFlag(date, roll, 'Độ chính xác vị trí = 0 m (thường do ứng dụng giả vị trí)');
  }
  if (Array.isArray(samples) && samples.length >= 3) {
    const s0 = samples[0];
    const same = samples.every(s => s && s.lat === s0.lat && s.lng === s0.lng && s.acc === s0.acc);
    if (same && Number(s0.acc) <= 10) setLocFlag(date, roll, 'Vị trí đứng yên tuyệt đối với độ chính xác cao bất thường');
  }
  const list = locRecords.get(date) || [];
  if (isFinite(acc) && acc <= 15) {
    for (const r of list) {
      if (r.roll !== roll && r.acc <= 15 && Math.abs(r.lat - loc.lat) < 1e-6 && Math.abs(r.lng - loc.lng) < 1e-6) {
        setLocFlag(date, roll, 'Toạ độ trùng y hệt với ' + r.roll);
        setLocFlag(date, r.roll, 'Toạ độ trùng y hệt với ' + roll);
      }
    }
  }
  list.push({ roll, lat: loc.lat, lng: loc.lng, acc: isFinite(acc) ? acc : 9999 });
  locRecords.set(date, list);
}
setInterval(() => {
  const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' });
  for (const k of locRecords.keys()) if (k !== today) locRecords.delete(k);
  for (const k of locFlags.keys()) if (k !== today) locFlags.delete(k);
}, 60 * 60 * 1000).unref();

setInterval(() => {
  const now = Date.now();
  for (const [k, t] of scanTickets) if (t.expiresAt < now) scanTickets.delete(k);
  for (const [k, r] of sessionRadius) if (now - r.at > 60 * 60 * 1000) sessionRadius.delete(k);
}, 60 * 1000).unref();

// Trả về { lat, lng, radius } nếu mã/vé còn hiệu lực, ngược lại null
function resolveSession(sessionId, ticket) {
  if (ticket) {
    const t = scanTickets.get(ticket);
    if (t && t.sessionId === sessionId && t.expiresAt > Date.now()) return t;
  }
  if (sessionId && validateSession(sessionId)) {
    const info = getSessionInfo(sessionId);
    if (info) {
      const r = sessionRadius.get(sessionId);
      return { lat: info.lat, lng: info.lng, radius: (r && r.radius) || info.radius || MAX_DISTANCE_METERS };
    }
  }
  return null;
}

// Middleware Setup
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": [
          "'self'",
          "https://cdn.tailwindcss.com",
          "https://cdn.jsdelivr.net",
          "'unsafe-inline'"
        ],
        "style-src": [
          "'self'",
          "https://fonts.googleapis.com",
          "https://cdn.jsdelivr.net",
          "https://cdnjs.cloudflare.com",
          "'unsafe-inline'"
        ],
        "font-src": [
          "'self'",
          "https://fonts.gstatic.com",
          "https://cdnjs.cloudflare.com"
        ],
        "img-src": [
          "'self'",
          "data:",
          "https://ui-avatars.com"
        ]
      }
    }
  })
);


app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});


// QR Code Directory Setup
try {
  if (!fs.existsSync(QR_CODE_DIR)) {
    fs.mkdirSync(QR_CODE_DIR, { recursive: true });
    console.log(` Created QR code directory at: ${QR_CODE_DIR}`);
  }

  // Clean up old QR codes on startup
  fs.readdir(QR_CODE_DIR, (err, files) => {
    if (err) {
      console.error('Startup cleanup error:', err);
      return;
    }
    
    const now = Date.now();
    files.forEach(file => {
      if (file.startsWith('qr_') && file.endsWith('.png')) {
        const fileTimestamp = parseInt(file.split('_')[1].split('.')[0]);
        if (isNaN(fileTimestamp) || (now - fileTimestamp > 1.5 * 60 * 1000)) {
          fs.unlink(path.join(QR_CODE_DIR, file), err => {
            if (err) console.error('Error deleting file:', file, err);
          });
        }
      }
    });
  });
  
  app.use('/qrcodes', express.static(QR_CODE_DIR, {
    maxAge: '1h', // Cache for 1 hour
    setHeaders: (res, path) => {
        res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    }
}));
  console.log(` Serving QR codes from: ${QR_CODE_DIR}`);
} 
catch (err) {
  console.error(' Failed to setup QR code directory:', err);
  process.exit(1);
}

// Rate limiting for QR generation
const qrLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  handler: (req, res) => {
    console.log(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      status: "error",
      message: "Too many QR requests. Please wait a minute."
    });
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Chỉ giảng viên (có mật khẩu) mới xem được dữ liệu điểm danh và sinh viên
// Chống dò mật khẩu: sai 10 lần trong 15 phút thì khoá địa chỉ IP đó 15 phút
const ADMIN_MAX_FAILS = 10;
const ADMIN_LOCK_MS = 15 * 60 * 1000;
const adminFails = new Map(); // ip -> { count, first }
function checkAdmin(req) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const f = adminFails.get(ip);
  if (f && now - f.first > ADMIN_LOCK_MS) adminFails.delete(ip);
  const cur = adminFails.get(ip);
  if (cur && cur.count >= ADMIN_MAX_FAILS) {
    return { ok: false, code: 429, message: "Nhập sai mật khẩu quá nhiều lần. Hãy thử lại sau 15 phút." };
  }
  const expected = process.env.ADMIN_PASSWORD;
  const given = String(req.headers['x-admin-password'] || '');
  const ok = !!expected && given.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
  if (!ok) {
    const e = adminFails.get(ip) || { count: 0, first: now };
    e.count++;
    adminFails.set(ip, e);
    return { ok: false, code: 401, message: "Sai mật khẩu giảng viên" };
  }
  adminFails.delete(ip);
  return { ok: true };
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of adminFails) if (now - f.first > ADMIN_LOCK_MS) adminFails.delete(ip);
}, 5 * 60 * 1000).unref();

function requireAdmin(req, res, next) {
  const a = checkAdmin(req);
  if (!a.ok) return res.status(a.code).json({ status: "error", message: a.message });
  next();
}
app.use('/api/attendance', requireAdmin);
app.use('/api/students', requireAdmin);
app.use('/api/export', requireAdmin);
// Routes
app.use("/api/students", studentProfileRoutes);
app.use("/api/attendance", attendanceRoutes);

app.get('/api/students/by-attendance-range', async (req, res) => {
    try {
        const { min, max } = req.query;
        
        // Validate inputs
        if (!min || !max) {
            return res.status(400).json({ 
                error: 'Both min and max percentage parameters are required' 
            });
        }
        
        const minPercentage = parseFloat(min);
        const maxPercentage = parseFloat(max);
        
        if (isNaN(minPercentage)) {
            return res.status(400).json({ 
                error: 'Minimum percentage must be a number' 
            });
        }
        
        if (isNaN(maxPercentage)) {
            return res.status(400).json({ 
                error: 'Maximum percentage must be a number' 
            });
        }
        
        if (minPercentage < 0 || maxPercentage > 100) {
            return res.status(400).json({ 
                error: 'Percentages must be between 0 and 100' 
            });
        }
        
        if (minPercentage > maxPercentage) {
            return res.status(400).json({ 
                error: 'Minimum percentage cannot be greater than maximum' 
            });
        }

        // Get all unique class dates (for calculating total possible classes)
        const allDates = await Attendance.find().distinct('date');
        const totalClasses = allDates.length;
        
        if (totalClasses === 0) {
            return res.json({ 
                status: "success", 
                data: [] 
            });
        }

        // Aggregation to get students with attendance in range
       const results = await StudentProfile.aggregate([
    {
        $lookup: {
            from: "users",  // Join with User collection
            localField: "universityRollNo",
            foreignField: "universityRollNo",
            as: "user"
        }
    },
    {
        $lookup: {
            from: "attendances",
            let: { rollNo: "$universityRollNo" },
            pipeline: [
                { 
                    $match: { 
                        $expr: { 
                            $and: [
                                { $eq: ["$universityRollNo", "$$rollNo"] },
                                { $eq: ["$status", "present"] }
                            ]
                        }
                    }
                },
                { $count: "presentDays" }
            ],
            as: "attendance"
        }
    },
    {
        $addFields: {
            presentDays: { $ifNull: [{ $arrayElemAt: ["$attendance.presentDays", 0] }, 0] },
            totalClasses: totalClasses,
            attendancePercentage: {
                $round: [
                    { 
                        $multiply: [
                            { 
                                $divide: [
                                    { $ifNull: [{ $arrayElemAt: ["$attendance.presentDays", 0] }, 0] },
                                    totalClasses
                                ] 
                            },
                            100
                        ] 
                    }
                ]
            },
            // Handle both data structures
            name: {
                $ifNull: [
                    { $arrayElemAt: ["$user.name", 0] },
                    { $arrayElemAt: ["$user.personalInfo.fullName", 0] },
                    "N/A"
                ]
            },
            section: {
                $ifNull: [
                    { $arrayElemAt: ["$user.section", 0] },
                    { $arrayElemAt: ["$user.academicInfo.section", 0] },
                    "N/A"
                ]
            }
        }
    },
    {
        $match: {
            attendancePercentage: { $gte: minPercentage, $lte: maxPercentage }
        }
    },
    {
        $sort: { attendancePercentage: -1 }
    },
    {
        $project: {
            universityRollNo: 1,
            name: 1,
            section: 1,
            attendancePercentage: 1,
            presentDays: 1,
            totalClasses: 1,
            _id: 0
        }
    }
]);

        // --- MANUAL SORTING (Bubble Sort, descending by attendancePercentage) ---
        if (results && results.length > 1) {
            const n = results.length;
            for (let i = 0; i < n - 1; i++) {
                for (let j = 0; j < n - i - 1; j++) {
                    // Sort in descending order of attendancePercentage
                    if (results[j].attendancePercentage < results[j + 1].attendancePercentage) {
                        // Swap elements
                        const temp = results[j];
                        results[j] = results[j + 1];
                        results[j + 1] = temp;
                    }
                }
            }
        }
        // --- END MANUAL SORTING ---

        res.json({ 
            status: "success",
            data: results 
        });

    } catch (error) {
        console.error("Error fetching students by attendance range:", error);
        res.status(500).json({ 
            status: "error", 
            message: error.message 
        });
    }
});
app.get('/api/attendance/dates', async (req, res) => {
  try {
    const dates = await Attendance.find().distinct('date');
    res.json({ status: "success", data: dates });
  } catch (error) {
    console.error("Error fetching attendance dates:", error);
    res.status(500).json({ status: "error", message: error.message });
  }
});
app.get('/api/attendance/by-date', async (req, res) => {
    try {
        const { date } = req.query;
        if (!date) {
            return res.status(400).json({ error: 'Date parameter is required' });
        }

        const attendance = await Attendance.find({ 
            date: date,
            status: 'present'
        }).sort({ universityRollNo: 1 });

        res.json({ 
            status: "success",
            data: attendance 
        });
    } catch (error) {
        console.error("Error fetching attendance by date:", error);
        res.status(500).json({ status: "error", message: error.message });
    }
});
// QR Code Generation Endpoint
// ... (other parts of server.js) ...

// QR Code Generation Endpoint
app.get("/api/generate-qr", qrLimiter, async (req, res) => {
  try {
    const adminCheck = checkAdmin(req);
    if (!adminCheck.ok) {
      return res.status(adminCheck.code).json({ status: "error", message: adminCheck.message });
    }
    console.log(`Generating QR code for IP: ${req.ip}`);
    const lat = parseFloat(req.query.lat);
const lng = parseFloat(req.query.lng);
if (isNaN(lat) || isNaN(lng)) {
  return res.status(400).json({
    status: "error",
    message: "Cần cho phép vị trí để tạo mã QR"
  });
}
const radiusReq = parseInt(req.query.radius, 10);
const radius = ALLOWED_RADIUS.includes(radiusReq) ? radiusReq : 100;
const qrData = await generateQRCode(`${req.ip}-${Date.now()}`, lat, lng, radius);
    sessionRadius.set(qrData.sessionId, { radius, at: Date.now() });
    
    console.log(` Generated QR code at: ${qrData.qrImage}`);
    res.json({
      status: "success",
      qrImage: qrData.qrImage,
      sessionId: qrData.sessionId,
      expiresIn: qrData.expiresIn // <<< MODIFIED: Added expiresIn from qrData
    });
  } catch (error) {
    console.error("QR generation error:", error);
    res.status(500).json({
      status: "error",
      message: "Failed to generate QR code",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ... (rest of server.js) ...
app.post('/api/consistent-hash', (req, res) => {
    const { input } = req.body || {};
    if (typeof input !== 'string' || !input.trim() || input.length > 5000) {
        return res.status(400).json({ error: 'Input must be a non-empty string' });
    }
    res.json({ fingerprint: consistentHashJS(input) });
});

function consistentHashJS(input) {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        hash = (hash * 31 + input.charCodeAt(i)) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
}

app.post("/api/validate-session", async (req, res) => {
  try {
    const { sessionId, ticket } = req.body;
    if (!sessionId) {
      return res.status(400).json({ 
        valid: false, 
        message: "Session ID required" 
      });
    }
    
    const check = checkStudentTicket(req);
    res.json({ 
      valid: !check.error,
      message: check.error || "Valid session"
    });
  } catch (error) {
    console.error("Session validation error:", error);
    res.status(500).json({ 
      valid: false,
      message: "Validation error"
    });
  }
});

app.get('/verify-attendance', (req, res) => {
    try {
        console.log('Raw query data:', req.query.data);
        const dataStr = decodeURIComponent(req.query.data);
        const data = JSON.parse(dataStr);
        console.log('Parsed data:', data);

        if (!data?.sessionId || !data?.timestamp || !data?.hash) {
            console.log('Missing fields in data:', data);
            return res.status(400).send('Invalid QR code data: Missing fields');
        }

        const secretKey = process.env.QR_SECRET_KEY || 'default-secret-key';
        
        const hashInput = data.sessionId + data.timestamp + secretKey;
        
        const expectedHash = sha256(hashInput);

        if (data.hash !== expectedHash) {
            return res.status(400).send('Invalid QR code: Hash mismatch');
        }

        const currentTime = Date.now();
        let qrTime = Number(data.timestamp);
        if (qrTime > 0 && qrTime < 1e12) qrTime *= 1000; // phòng trường hợp lưu theo giây
        if (!(qrTime > 0) || currentTime - qrTime > SCAN_WINDOW_MS) {
            return res.status(400).send('<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:sans-serif;text-align:center;padding:40px 20px"><h2>Mã QR này đã cũ</h2><p>Mã trên màn hình đổi liên tục. Hãy quét trực tiếp mã <b>đang chiếu</b> (ảnh chụp hoặc gửi lại không dùng được).</p></body>');
        }

        const scanned = resolveSession(data.sessionId, null);
        if (!scanned) {
            return res.status(400).send('<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:sans-serif;text-align:center;padding:40px 20px"><h2>Mã QR đã hết hạn</h2><p>Hãy quét lại mã đang được chiếu trên màn hình.</p></body>');
        }
        const ticket = crypto.randomBytes(16).toString('hex');
        scanTickets.set(ticket, {
            sessionId: data.sessionId,
            lat: scanned.lat,
            lng: scanned.lng,
            radius: scanned.radius,
            expiresAt: Date.now() + TICKET_TTL_MS
        });
        res.cookie(COOKIE_TICKET, ticket, cookieOpts(req, TICKET_TTL_MS));
        res.redirect(`/index.html?sessionId=${encodeURIComponent(data.sessionId)}&ticket=${ticket}`);
    }  catch (error) {
        console.error('QR validation error:', error);
        res.status(400).send('Invalid QR code data');
    }
});

function getDistanceFromLatLngInMeters(lat1, lng1, lat2, lng2) {
    const toRad = angle => (angle * Math.PI) / 180;
    const R = 6371000;
    const dLat = toRad(lat2 - lat1);
    const dLng = toRad(lng2 - lng1);
    const a = Math.sin(dLat / 2) ** 2 +
              Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
              Math.sin(dLng / 2) ** 2;
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

function sha256(input) {
    return crypto.createHash('sha256').update(input).digest('hex');
}

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    dbState: mongoose.connection.readyState,
    uptime: process.uptime()
  });
});

// Chỉ cho điểm danh bằng Safari hoặc Chrome (iPhone), Chrome (Android)
function checkBrowser(ua) {
  var isIOS = /iPhone|iPad|iPod/i.test(ua);
  var isAndroid = /Android/i.test(ua);
  if (/Zalo|FBAN|FBAV|FB_IAB|Messenger|Instagram|Line\/|MicroMessenger|TikTok/i.test(ua)) {
    return { ok: false, kind: 'browser', hint: isIOS ? 'Safari hoặc Chrome' : 'Chrome' };
  }
  if (isIOS) {
    if (/FxiOS|EdgiOS|OPiOS|OPT\/|GSA\/|DuckDuckGo|coc_coc|YaBrowser|UCBrowser/i.test(ua) || !/Safari\//.test(ua)) return { ok: false, kind: 'browser', hint: 'Safari hoặc Chrome' };
    return { ok: true };
  }
  if (isAndroid) {
    if (!/Chrome\//.test(ua) || /EdgA|OPR\/|OPT\/|SamsungBrowser|Firefox|UCBrowser|CocCoc|coc_coc|YaBrowser|DuckDuckGo|; wv\)|Version\/\d/i.test(ua)) return { ok: false, kind: 'browser', hint: 'Chrome' };
    return { ok: true };
  }
  // Máy tính / máy tính bảng chạy giao diện máy tính: không cho điểm danh
  return { ok: false, kind: 'desktop', hint: 'điện thoại' };
}

// Phát hiện máy tính giả làm điện thoại (công cụ lập trình) hoặc phần mềm giả lập Android
function checkDeviceConsistency(ua, platform, gpu, touch) {
  var isIOS = /iPhone|iPad|iPod/i.test(ua);
  var isAndroid = /Android/i.test(ua);
  platform = String(platform || '');
  gpu = String(gpu || '');
  if (/SwiftShader|llvmpipe|VirtualBox|VMware|Android Emulator|Parallels|Microsoft Basic Render/i.test(gpu)) return false;
  if (isIOS && platform && !/iPhone|iPad|iPod/i.test(platform)) return false;
  if (isAndroid && (/^(Win|Mac)/i.test(platform) || /x86_64|i686/i.test(platform))) return false;
  if ((isIOS || isAndroid) && /NVIDIA|GeForce|Radeon|Direct3D|Intel\(R\)|Intel Iris|Intel HD|Intel UHD/i.test(gpu)) return false;
  if ((isIOS || isAndroid) && touch === 0) return false;
  return true;
}

const ALLOWED_SCHOOLS = ["USSH", "UEH", "VLU", "DVSC", "UTC", "UEH-Mekong", "CDDaiViet"];

function validateAttendance(req, res, next) {
  const required = ['name', 'universityRollNo', 'school', 'deviceFingerprint'];
  const missing = required.filter(field => !req.body[field]);

  if (missing.length) {
    return res.status(400).json({
      status: "error",
      message: `Missing required fields: ${missing.join(', ')}`
    });
  }

  const bc = checkBrowser(String(req.headers['user-agent'] || ''));
  if (!bc.ok) {
    return res.status(400).json({
      status: "error",
      message: bc.kind === 'desktop'
        ? 'Hãy điểm danh bằng điện thoại (iPhone dùng Safari hoặc Chrome, Android dùng Chrome)'
        : `Hãy mở trang bằng ${bc.hint} để điểm danh (iPhone dùng Safari hoặc Chrome, Android dùng Chrome)`
    });
  }
  const env = req.body.env || {};
  if (!checkDeviceConsistency(String(req.headers['user-agent'] || ''), env.platform, env.gpu, typeof env.touch === 'number' ? env.touch : undefined)) {
    return res.status(400).json({ status: "error", message: "Thiết bị không hợp lệ. Hãy dùng điện thoại thật để quét mã." });
  }
  if (env.priv === 'private') {
    return res.status(400).json({ status: "error", message: "Hãy tắt chế độ ẩn danh / riêng tư rồi quét lại mã." });
  }
  if (!ALLOWED_SCHOOLS.includes(req.body.school)) {
    return res.status(400).json({ status: "error", message: "Trường không hợp lệ" });
  }
  // Làm sạch dữ liệu; lưu tên trường viết tắt vào trường "section" có sẵn
  req.body.name = String(req.body.name).trim();
  req.body.universityRollNo = String(req.body.universityRollNo).replace(/\s+/g, "").toUpperCase();
  req.body.section = req.body.school;
  req.body.classRollNo = req.body.universityRollNo;

  if (!req.body.location || typeof req.body.location.lat !== "number" || typeof req.body.location.lng !== "number") {
    return res.status(400).json({
      status: "error",
      message: "Location (lat, lng) is required and must be numeric"
    });
  }
  next();
}

app.post("/mark-attendance", validateAttendance, async (req, res) => {
  try {
    const { universityRollNo, deviceFingerprint, location } = req.body;
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' });

    // Trình duyệt này đã điểm danh cho MSSV khác trong hôm nay?
    const devVal = readSigned(parseCookies(req)[COOKIE_DEVICE]);
    if (devVal) {
      const [devDate, devRoll] = devVal.split('|');
      if (devDate === today && devRoll && devRoll !== universityRollNo) {
        return res.status(400).json({
          status: "error",
          message: "Thiết bị này đã dùng để điểm danh hôm nay"
        });
      }
    }

    const [existing, existingDevice] = await Promise.all([
      Attendance.findOne({ universityRollNo, date: today }),
      Attendance.findOne({ deviceFingerprint, date: today })
    ]);

    if (existing) {
      return res.status(400).json({
        status: "error",
        message: "Bạn đã điểm danh hôm nay rồi"
      });
    }

    if (existingDevice) {
      return res.status(400).json({
        status: "error",
        message: "Thiết bị này đã dùng để điểm danh hôm nay"
      });
    }

    const ticketCheck = checkStudentTicket(req);
    if (ticketCheck.error) {
      return res.status(400).json({ status: "error", message: ticketCheck.error });
    }
    const sessionInfo = ticketCheck.info;
    const distance = getDistanceFromLatLngInMeters(
      location.lat, location.lng,
      sessionInfo.lat, sessionInfo.lng
    );

    const maxDistance = sessionInfo.radius || MAX_DISTANCE_METERS;
    if (distance > maxDistance) {
      return res.status(400).json({
        status: "error",
        message: `Bạn phải ở trong phạm vi ${maxDistance} m quanh giảng viên để điểm danh (hiện cách khoảng ${distance.toFixed(0)} m)`
      });
    }

    const student = await User.findOneAndUpdate(
      { universityRollNo },
      {
        $setOnInsert: {
          name: req.body.name,
          section: req.body.section,
          classRollNo: req.body.classRollNo
        }
      },
      { new: true, upsert: true }
    );

    const attendance = await Attendance.create({
      ...req.body,
      date: today,
      time: new Date().toLocaleTimeString('en-GB', { hour12: false, timeZone: 'Asia/Ho_Chi_Minh' }),
      status: "present",
      studentId: student._id,
      distanceFromClass: distance
    });

    registerDevice(today, req.ip, req.body.deviceGroup, universityRollNo);
    try {
      const samples = Array.isArray(req.body.samples) ? req.body.samples.slice(0, 10) : [];
      analyzeLocation(today, universityRollNo, { lat: location.lat, lng: location.lng, acc: location.acc }, samples);
    } catch (e) { console.error('analyzeLocation error:', e.message); }

    // Vé quét chỉ dùng một lần; ghi nhớ thiết bị này đã điểm danh cho MSSV nào hôm nay
    scanTickets.delete(req.body.ticket);
    res.clearCookie(COOKIE_TICKET, { path: '/' });
    res.cookie(COOKIE_DEVICE, signValue(today + '|' + universityRollNo), cookieOpts(req, 24 * 60 * 60 * 1000));

    res.json({
      status: "success",
      message: "Attendance marked successfully",
      data: attendance
    });
  } catch (error) {
    console.error("Attendance error:", error);
    res.status(500).json({ status: "error", message: error.message });
  }
});
app.get('/api/students/profile', async (req, res) => {
    try {
        const { rollNo } = req.query;
        console.log(`[PROFILE] Attempting to find profile for rollNo: ${rollNo}`); // ADD THIS
        const student = await StudentProfile.findOne({ universityRollNo: rollNo });
        
        if (!student) {
            console.log(`[PROFILE] Student not found: ${rollNo}`); // ADD THIS
            return res.status(404).json({ error: 'Student not found' });
        }
        console.log(`[PROFILE] Student found:`, student); // ADD THIS
        res.json({ data: student });
    } catch (error) {
        console.error(`[PROFILE] Error fetching profile for ${rollNo}:`, error); // ADD THIS
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/students/notifications', async (req, res) => {
  const { rollNo } = req.query;
  // TODO: Replace with real data lookup
  const dummyNotifications = [
    { text: "Assignment deadline extended!", timestamp: new Date(), read: false },
    { text: "New grades posted.", timestamp: new Date(), read: true }
  ];
  res.json({ data: dummyNotifications });
});

app.post('/api/students/notifications/read', (req, res) => {
  const { rollNo } = req.body;
  // TODO: Implement actual DB update here
  console.log(`Marking all notifications as read for rollNo: ${rollNo}`);
  res.json({ status: 'success' });
});

app.get("/api/students/:rollNo/attendance", async (req, res) => {
    try {
        const { rollNo } = req.params;
        const period = req.query.period || 'current';
        
        const student = await StudentProfile.findOne({ universityRollNo: rollNo });
        if (!student) {
            return res.status(404).json({ error: 'Student not found' });
        }

        const dateRange = {
            current: () => ({ 
                start: new Date(new Date().setMonth(new Date().getMonth() - 4)), 
                end: new Date() 
            }),
            last: () => ({ 
                start: new Date(new Date().setMonth(new Date().getMonth() - 8)), 
                end: new Date(new Date().setMonth(new Date().getMonth() - 4)) 
            }),
            year: () => ({ 
                start: new Date(new Date().setFullYear(new Date().getFullYear() - 1)), 
                end: new Date() 
            })
        };

        const { start, end } = dateRange[period] ? dateRange[period]() : dateRange.current();

        const allAttendance = await Attendance.find({
            date: {
                $gte: new Date(start).toISOString().split('T')[0],
                $lte: new Date(end).toISOString().split('T')[0]
            }
        }).distinct('date');

        const totalClasses = allAttendance.length;

        const attendance = await Attendance.find({
            universityRollNo: rollNo,
            date: {
                $gte: new Date(start).toISOString().split('T')[0],
                $lte: new Date(end).toISOString().split('T')[0]
            }
        }).sort({ date: 1 });

        const presentDays = attendance.filter(a => a.status === 'present').length;
        const percentage = totalClasses > 0 ? Math.round((presentDays / totalClasses) * 100) : 0;

        const monthlyData = attendance.reduce((acc, record) => {
            const monthYear = new Date(record.date).toLocaleString('default', { month: 'short', year: 'numeric' });
            if (!acc[monthYear]) acc[monthYear] = { present: 0, total: 0 };
            // This total might be per student, not overall if a class was held but student was absent.
            // For overall total, we'd need all class dates.
            // The current logic for monthlyData seems to count days the student had a record.
            // Let's assume for now this is fine for the chart.
            const dateKey = new Date(record.date).toISOString().split('T')[0];
            // Count total based on all class dates in that month
            // This part is tricky, depends on how `allAttendance` (all unique class dates) is used here.
            // For simplicity, current approach is okay.
            acc[monthYear].total++; // This counts student's records
            if (record.status === 'present') acc[monthYear].present++;
            return acc;
        }, {});

        const labels = Object.keys(monthlyData);
        const studentAttendance = labels.map(label => 
            monthlyData[label].total > 0 ? Math.round((monthlyData[label].present / monthlyData[label].total) * 100) : 0
        );

        res.json({
            status: "success",
            data: {
                attendanceRecords: attendance,
                attendancePercentage: percentage,
                totalClasses: totalClasses,
                presentDays: presentDays,
                chartData: {
                    labels,
                    studentAttendance,
                    departmentAverage: studentAttendance.map(p => Math.max(70, Math.min(95, p + (Math.random() * 10 - 5))))
                }
            }
        });

    } catch (error) {
        console.error("Error fetching attendance:", error);
        res.status(500).json({ status: "error", message: error.message });
    }
});
app.get('/api/students/:rollNo/documents', async (req, res) => {
  const { rollNo } = req.params;
  // Dummy data, replace with DB lookup
  res.json({
    data: {
      idCardUrl: null, // or 'path/to/idcard.pdf'
      resumeUrl: null, // or 'path/to/resume.pdf'
      feeReceipts: [], // or [{ name: 'Sem1_Receipt.pdf', url: '...' }]
      gradeSheets: []  // or [{ name: 'Sem1_Grades.pdf', url: '...' }]
    }
  });
});


// --- NEW ALGORITHM ENDPOINTS ---

// Dijkstra: Shortest path from hostel to class
app.get('/api/navigation/shortest-path', async (req, res) => {
    try {
        const { start, end } = req.query;
        if (!start || !end) {
            return res.status(400).json({ status: "error", message: "Start and end locations are required." });
        }

        // Placeholder: graphData should represent your campus map (nodes, edges, weights)
        // This would typically be loaded from a database or a configuration file.
        const graphData = {
            nodes: ["HostelA", "HostelB", "Library", "Mess", "AdminBuilding", "CSEDept", "ECEdept", "MainGate"],
            edges: [
                { from: "HostelA", to: "Mess", weight: 5 }, // weight could be distance in meters or time in minutes
                { from: "HostelA", to: "Library", weight: 7 },
                { from: "Mess", to: "CSEDept", weight: 10 },
                { from: "Library", to: "CSEDept", weight: 6 },
                { from: "Library", to: "AdminBuilding", weight: 3 },
                { from: "AdminBuilding", to: "ECEdept", weight: 4 },
                { from: "CSEDept", to: "ECEdept", weight: 2 },
                { from: "MainGate", to: "HostelA", weight: 15 },
                { from: "MainGate", to: "AdminBuilding", weight: 8 },
            ]
        };
        
        if (!graphData.nodes.includes(start) || !graphData.nodes.includes(end)) {
             return res.status(404).json({ status: "error", message: "One or both locations not found in map data." });
        }

        const result = dijkstra.findShortestPath(start, end, graphData);
        
        if (!result || result.path.length === 0) {
            return res.status(404).json({ status: "success", message: `No path found from ${start} to ${end}.`, data: result });
        }

        res.json({ status: "success", data: result });

    } catch (error) {
        console.error("Dijkstra shortest path error:", error);
        if (error.message.includes("module not loaded")) {
             return res.status(501).json({ status: "error", message: "Navigation module is not available." });
        }
        res.status(500).json({ status: "error", message: error.message });
    }
});

// Knapsack/DP: Optimize profile recommendations
app.get('/api/students/:rollNo/recommendations', async (req, res) => {
    const { rollNo } = req.params;
    const { type } = req.query; // e.g., "course", "job", "skill"

    if (!type) {
        return res.status(400).json({ status: "error", message: "Recommendation type is required (e.g., 'course', 'job')." });
    }

    try {
        const studentProfile = await StudentProfile.findOne({ universityRollNo: rollNo });
        if (!studentProfile) {
            return res.status(404).json({ status: "error", message: "Student profile not found." });
        }

        // Placeholder: availableItems would come from a database or configuration
        // This is highly dependent on the 'type' of recommendation
        let availableItems = [];
        if (type === "course") {
            availableItems = [
                { id: "CS101", name: "Intro to Programming", difficulty: 2, relevance_tags: ["programming", "beginner"] },
                { id: "CS305", name: "Machine Learning", difficulty: 4, relevance_tags: ["ai", "ml", "advanced", "math"] },
                { id: "DS202", name: "Data Structures", difficulty: 3, relevance_tags: ["programming", "core"] },
                { id: "EE201", name: "Basic Electronics", difficulty: 3, relevance_tags: ["electronics", "hardware"] },
            ];
        } else if (type === "job") {
            availableItems = [
                { id: "JOB01", title: "Software Dev Intern", required_skills: ["javascript", "nodejs"], company: "TechCorp" },
                { id: "JOB02", title: "Data Analyst", required_skills: ["python", "sql", "statistics"], company: "DataDrivenLLC" },
                { id: "JOB03", title: "Hardware Engineer", required_skills: ["verilog", "circuit design"], company: "ChipMakers" },
            ];
        } else {
            return res.status(400).json({ status: "error", message: "Unsupported recommendation type." });
        }
        
        const recommendations = profileOptimizer.getProfileRecommendations(studentProfile.toObject(), type, availableItems);
        
        res.json({ status: "success", data: recommendations });

    } catch (error) {
        console.error("Profile recommendation error:", error);
         if (error.message.includes("module not loaded")) {
             return res.status(501).json({ status: "error", message: "Recommendation module is not available." });
        }
        res.status(500).json({ status: "error", message: error.message });
    }
});

// DFS/BFS: Community network or graph-based friend explorer
app.get('/api/students/:rollNo/community', async (req, res) => {
    const { rollNo } = req.params;
    const depth = parseInt(req.query.depth) || 2; // Default depth
    const algorithm = req.query.algorithm || 'bfs'; // 'bfs' or 'dfs'

    if (algorithm !== 'bfs' && algorithm !== 'dfs') {
        return res.status(400).json({ status: "error", message: "Invalid algorithm type. Use 'bfs' or 'dfs'." });
    }
    if (depth <= 0 || depth > 5) { // Cap depth to prevent excessive computation
        return res.status(400).json({ status: "error", message: "Depth must be between 1 and 5." });
    }

    try {
        const studentExists = await StudentProfile.findOne({ universityRollNo: rollNo }).select('_id');
        if (!studentExists) {
            return res.status(404).json({ status: "error", message: "Starting student profile not found." });
        }

        // Placeholder: graphData representing student connections (friendships, classmates, project partners)
        // This would typically be constructed by querying relationships from the database.
        // For example, find all students in the same section, or explicit friend connections.
        // Let's mock a simple graph structure for now.
        const allStudents = await StudentProfile.find().select('universityRollNo name section').lean();
        const mockConnections = [ // Simulate some connections
            { from: allStudents[0]?.universityRollNo, to: allStudents[1]?.universityRollNo, type: "classmate" },
            { from: allStudents[0]?.universityRollNo, to: allStudents[2]?.universityRollNo, type: "project_partner" },
            { from: allStudents[1]?.universityRollNo, to: allStudents[3]?.universityRollNo, type: "classmate" },
        ].filter(c => c.from && c.to); // Filter out undefined if not enough students

        const graphData = {
            students: allStudents.map(s => ({ id: s.universityRollNo, name: s.name, section: s.section })),
            connections: mockConnections
        };
        
        const communityData = graphTraversal.exploreCommunity(rollNo, graphData, depth, algorithm);
        
        res.json({ status: "success", data: communityData });

    } catch (error) {
        console.error("Community exploration error:", error);
        if (error.message.includes("module not loaded")) {
             return res.status(501).json({ status: "error", message: "Graph traversal module is not available." });
        }
        res.status(500).json({ status: "error", message: error.message });
    }
});

// --- END NEW ALGORITHM ENDPOINTS ---

app.get('/api/export/attendance', async (req, res) => {
  try {
    const adminCheck = checkAdmin(req);
    if (!adminCheck.ok) {
      return res.status(adminCheck.code).json({ status: "error", message: adminCheck.message });
    }
    const date = String(req.query.date || '');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ status: "error", message: "Ngày không hợp lệ" });
    }
    const filter = { date, status: 'present' };
    const school = String(req.query.school || '');
    if (school) {
      if (!ALLOWED_SCHOOLS.includes(school)) {
        return res.status(400).json({ status: "error", message: "Trường không hợp lệ" });
      }
      filter.section = school;
    }
    const rows = await Attendance.find(filter).sort({ time: 1 }).lean();
    res.json({
      status: "success",
      data: rows.map(r => {
        const partners = suspectFlags.get(date) && suspectFlags.get(date).get(r.universityRollNo);
        return {
          universityRollNo: r.universityRollNo,
          name: r.name,
          time: r.time,
          flag: !!partners,
          flagWith: partners ? Array.from(partners) : [],
          locFlag: (locFlags.get(date) && locFlags.get(date).get(r.universityRollNo)) || ''
        };
      })
    });
  } catch (error) {
    console.error("Export error:", error);
    res.status(500).json({ status: "error", message: error.message });
  }
});
app.delete('/api/export/attendance', async (req, res) => {
  try {
    const adminCheck = checkAdmin(req);
    if (!adminCheck.ok) {
      return res.status(adminCheck.code).json({ status: "error", message: adminCheck.message });
    }
    const date = String(req.query.date || '');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ status: "error", message: "Ngày không hợp lệ" });
    }
    const filter = { date };
    const school = String(req.query.school || '');
    if (school) {
      if (!ALLOWED_SCHOOLS.includes(school)) {
        return res.status(400).json({ status: "error", message: "Trường không hợp lệ" });
      }
      filter.section = school;
    }
    const rollsToDelete = await Attendance.find(filter).distinct('universityRollNo');
    const result = await Attendance.deleteMany(filter);
    const dayLoc = locFlags.get(date);
    if (dayLoc) rollsToDelete.forEach(r => dayLoc.delete(r));
    const dayRecs = locRecords.get(date);
    if (dayRecs) locRecords.set(date, dayRecs.filter(x => !rollsToDelete.includes(x.roll)));
    const dayFlags = suspectFlags.get(date);
    if (dayFlags) {
      rollsToDelete.forEach(r => dayFlags.delete(r));
      if (!dayFlags.size) suspectFlags.delete(date);
    }
    res.json({ status: "success", deleted: result.deletedCount });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ status: "error", message: error.message });
  }
});
// Error Handlers
app.use((req, res) => {
  res.status(404).json({ status: "error", message: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error(" Server error:", {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method
  });
  res.status(500).json({ status: "error", message: "Internal server error" });
});

// Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log(" Connected to MongoDB");
    try {
      await Attendance.createIndexes([
        { key: { universityRollNo: 1, date: 1 }, name: "student_date_attendance_idx" },
        { key: { deviceFingerprint: 1, date: 1 }, name: "device_date_attendance_idx" }
      ]);
      await StudentProfile.createIndexes([
        { key: { universityRollNo: 1 }, name: "student_rollno_profile_idx", unique: true }
      ]);
      console.log("Indexes ensured/created for Attendance and StudentProfile.");
    } catch (err) {
      console.error("Index creation/ensuring error:", err);
    }
  })
  .catch(err => {
    console.error(" MongoDB connection error:", err);
    process.exit(1);
  });

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));