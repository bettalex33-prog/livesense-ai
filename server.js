const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'livesense-super-secret-key-2026';
const FHIR_BASE  = 'https://hapi.fhir.org/baseR4';

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'hospital.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    name TEXT NOT NULL, role TEXT NOT NULL, department TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, room TEXT NOT NULL, ward TEXT NOT NULL,
    date_of_birth TEXT, blood_type TEXT, fhir_id TEXT,
    condition TEXT DEFAULT 'Stable',
    admitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    discharged_at DATETIME, status TEXT DEFAULT 'active'
  );
  CREATE TABLE IF NOT EXISTS vitals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    heart_rate REAL, blood_pressure REAL, oxygen_saturation REAL, temperature REAL,
    source TEXT DEFAULT 'simulator',
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS ai_diagnoses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    vitals_snapshot TEXT NOT NULL,
    diagnosis TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    model TEXT DEFAULT 'claude-sonnet-4-20250514',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, action TEXT NOT NULL, details TEXT, ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Seed users with more roles ────────────────────────────────────────────────
if (db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0) {
  const ins = db.prepare('INSERT INTO users (username,password_hash,name,role,department) VALUES (?,?,?,?,?)');
  ins.run('dr.smith',     bcrypt.hashSync('doctor123', 10), 'Dr. Emily Smith',    'Doctor',       'Cardiology');
  ins.run('dr.johnson',   bcrypt.hashSync('doctor123', 10), 'Dr. Marcus Johnson', 'Doctor',       'ICU');
  ins.run('nurse.alex',   bcrypt.hashSync('nurse123',  10), 'Nurse Alex Kim',     'Nurse',        'ICU');
  ins.run('nurse.sara',   bcrypt.hashSync('nurse123',  10), 'Nurse Sara Osei',    'Nurse',        'General');
  ins.run('pharmacist',   bcrypt.hashSync('pharma123', 10), 'Dr. Priya Nair',     'Pharmacist',   'Pharmacy');
  ins.run('radiologist',  bcrypt.hashSync('radio123',  10), 'Dr. James Park',     'Radiologist',  'Radiology');
  ins.run('admin',        bcrypt.hashSync('admin123',  10), 'Admin Portal',       'Admin',        'Administration');
  console.log('✅ 7 users seeded (Doctor x2, Nurse x2, Pharmacist, Radiologist, Admin)');
}

// ── Seed patients ─────────────────────────────────────────────────────────────
if (db.prepare('SELECT COUNT(*) as c FROM patients').get().c === 0) {
  const ins = db.prepare('INSERT INTO patients (name,room,ward,date_of_birth,blood_type,condition) VALUES (?,?,?,?,?,?)');
  [
    ['John Doe',         '301A','Cardiology','1958-03-12','A+', 'Atrial Fibrillation'],
    ['Sarah Smith',      '302B','General',   '1975-07-24','O+', 'Pneumonia'],
    ['Michael Chen',     '303A','ICU',       '1990-11-05','B-', 'Post-Op Recovery'],
    ['Emma Wilson',      '304C','Neurology', '1965-01-30','AB+','Migraine'],
    ['Carlos Rivera',    '305B','Cardiology','1952-09-18','O-', 'Hypertension'],
    ['Aisha Okafor',     '306A','General',   '1988-04-22','A-', 'Appendicitis'],
    ['Liam Nguyen',      '307D','ICU',       '1995-12-03','B+', 'Sepsis'],
    ['Fatima Al-Hassan', '308A','Neurology', '1970-06-14','AB-','Stroke Recovery'],
  ].forEach(p => ins.run(...p));
  console.log('✅ 8 patients seeded');
}

// ── Role permissions ──────────────────────────────────────────────────────────
const ROLE_PERMISSIONS = {
  Doctor:      ['view_patients','view_vitals','add_notes','discharge','run_ai','view_ai','admit'],
  Nurse:       ['view_patients','view_vitals','add_notes','run_ai','view_ai'],
  Pharmacist:  ['view_patients','view_vitals','view_ai'],
  Radiologist: ['view_patients','view_vitals'],
  Admin:       ['view_patients','view_vitals','add_notes','discharge','run_ai','view_ai','admit','view_audit','manage_users'],
};

const can = (role, permission) => (ROLE_PERMISSIONS[role] || []).includes(permission);

// ── Auth middleware ────────────────────────────────────────────────────────────
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(403).json({ error: 'Invalid token.' }); }
};

const requirePerm = (perm) => (req, res, next) => {
  if (!can(req.user.role, perm)) return res.status(403).json({ error: `Role '${req.user.role}' cannot perform: ${perm}` });
  next();
};

const audit = (uid, action, details, ip) =>
  db.prepare('INSERT INTO audit_log (user_id,action,details,ip_address) VALUES (?,?,?,?)').run(uid, action, details, ip);

// ── FHIR helper ───────────────────────────────────────────────────────────────
const fetchFHIR = (path) => new Promise((resolve, reject) => {
  https.get(`${FHIR_BASE}${path}`, { headers:{ Accept:'application/fhir+json' } }, res => {
    let data=''; res.on('data',c=>data+=c); res.on('end',()=>{ try{resolve(JSON.parse(data));}catch(e){reject(e);} });
  }).on('error',reject);
});

const parseFHIRPatient = (r) => ({
  fhir_id: r.id,
  name: r.name?.[0] ? [r.name[0].given?.join(' '),r.name[0].family].filter(Boolean).join(' ') : 'Unknown',
  dob: r.birthDate||'—', gender: r.gender||'—',
  language: r.communication?.[0]?.language?.text||'—',
  address: r.address?.[0] ? [r.address[0].city,r.address[0].state,r.address[0].country].filter(Boolean).join(', ') : '—',
});

// ── Device Simulator ──────────────────────────────────────────────────────────
const clamp = (v,lo,hi) => Math.max(lo,Math.min(hi,v));
const PROFILES = {
  'Atrial Fibrillation': { hrBase:95,hrVar:25,bpBase:135,bpVar:15,o2Base:95,o2Var:3,tempBase:37.0,ecg:'afib'   },
  'Pneumonia':           { hrBase:90,hrVar:10,bpBase:118,bpVar:8, o2Base:91,o2Var:4,tempBase:38.8,ecg:'normal' },
  'Post-Op Recovery':    { hrBase:72,hrVar:8, bpBase:115,bpVar:10,o2Base:97,o2Var:2,tempBase:37.2,ecg:'normal' },
  'Migraine':            { hrBase:65,hrVar:6, bpBase:120,bpVar:8, o2Base:98,o2Var:1,tempBase:37.1,ecg:'normal' },
  'Hypertension':        { hrBase:80,hrVar:8, bpBase:155,bpVar:12,o2Base:96,o2Var:2,tempBase:37.0,ecg:'normal' },
  'Appendicitis':        { hrBase:88,hrVar:10,bpBase:122,bpVar:8, o2Base:97,o2Var:2,tempBase:38.3,ecg:'normal' },
  'Sepsis':              { hrBase:115,hrVar:15,bpBase:95,bpVar:12,o2Base:90,o2Var:5,tempBase:39.5,ecg:'tachy'  },
  'Stroke Recovery':     { hrBase:68,hrVar:6, bpBase:145,bpVar:10,o2Base:95,o2Var:3,tempBase:37.3,ecg:'normal' },
  'Stable':              { hrBase:72,hrVar:5, bpBase:120,bpVar:6, o2Base:98,o2Var:1,tempBase:36.8,ecg:'normal' },
};

const generateECG = (pattern) => {
  const pts=[], total=80, beatsPerWindow=pattern==='tachy'?4:pattern==='afib'?3:2;
  for(let i=0;i<total;i++){
    const t=(i/total)*beatsPerWindow*Math.PI*2, beat=t%(Math.PI*2);
    let v=0;
    if(pattern==='afib'){
      const n=Math.sin(t*8)*0.05;
      if(beat>1.8&&beat<2.0)v=0.8+n;
      else if(beat>2.0&&beat<2.2)v=-0.2+n;
      else if(beat>2.5&&beat<2.9)v=0.15+n;
      else v=n*0.5+Math.sin(t*15)*0.03;
    } else if(pattern==='tachy'){
      if(beat>0.3&&beat<0.4)v=0.15;
      else if(beat>1.5&&beat<1.6)v=1.0;
      else if(beat>1.6&&beat<1.7)v=-0.3;
      else if(beat>2.0&&beat<2.4)v=0.2;
      else v=Math.random()*0.02-0.01;
    } else {
      if(beat>0.4&&beat<0.55)v=0.15;
      else if(beat>1.8&&beat<1.9)v=0.12;
      else if(beat>1.9&&beat<2.0)v=1.0;
      else if(beat>2.0&&beat<2.1)v=-0.25;
      else if(beat>2.4&&beat<2.9)v=0.25;
      else v=Math.random()*0.015-0.0075;
    }
    pts.push(parseFloat(v.toFixed(3)));
  }
  return pts;
};

const generateSpO2Wave = (o2) => {
  const pts=[];
  for(let i=0;i<40;i++){
    const t=(i/40)*Math.PI*4, base=(o2-100)/10;
    pts.push(parseFloat((base+Math.sin(t)*0.4+Math.sin(t*2)*0.1+Math.random()*0.05).toFixed(3)));
  }
  return pts;
};

const simulatePatient = (patient) => {
  const profile = PROFILES[patient.condition] || PROFILES['Stable'];
  const n = () => (Math.random()-0.5);
  const hr   = Math.round(clamp(profile.hrBase+n()*profile.hrVar,   30,200));
  const bp   = Math.round(clamp(profile.bpBase+n()*profile.bpVar,   60,200));
  const o2   = Math.round(clamp(profile.o2Base+n()*profile.o2Var,   70,100));
  const temp = parseFloat(clamp(profile.tempBase+n()*0.3, 34, 42).toFixed(1));
  db.prepare('INSERT INTO vitals (patient_id,heart_rate,blood_pressure,oxygen_saturation,temperature,source) VALUES (?,?,?,?,?,?)').run(patient.id,hr,bp,o2,temp,`simulator:${profile.ecg}`);
  return { id:patient.id, condition:patient.condition, vitals:{hr,bp,o2,temp}, ecg_waveform:generateECG(profile.ecg), spo2_waveform:generateSpO2Wave(o2), ecg_pattern:profile.ecg };
};

// ── AI DIAGNOSIS via Anthropic API ────────────────────────────────────────────
const callClaude = (messages, systemPrompt) => new Promise((resolve, reject) => {
  const body = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1000,
    system: systemPrompt,
    messages,
  });

  const req = https.request({
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY || '',
      'anthropic-version': '2023-06-01',
      'Content-Length': Buffer.byteLength(body),
    }
  }, res => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
      try {
        const parsed = JSON.parse(data);
        if (parsed.error) reject(new Error(parsed.error.message));
        else resolve(parsed.content[0].text);
      } catch(e) { reject(e); }
    });
  });
  req.on('error', reject);
  req.write(body);
  req.end();
});

app.post('/ai/diagnose/:id', authenticate, requirePerm('run_ai'), async (req, res) => {
  const patient = db.prepare('SELECT * FROM patients WHERE id=?').get(req.params.id);
  if (!patient) return res.status(404).json({ error: 'Patient not found.' });

  const { hr, bp, o2, temp } = req.body;

  // Get recent notes for context
  const recentNotes = db.prepare(`
    SELECT n.content, u.name, u.role FROM notes n
    JOIN users u ON n.user_id=u.id
    WHERE n.patient_id=? ORDER BY n.created_at DESC LIMIT 3
  `).all(req.params.id);

  // Get vitals history
  const vitalsHistory = db.prepare(`
    SELECT heart_rate,blood_pressure,oxygen_saturation,temperature,recorded_at
    FROM vitals WHERE patient_id=? ORDER BY recorded_at DESC LIMIT 10
  `).all(req.params.id);

  const systemPrompt = `You are an AI clinical decision support system integrated into a hospital monitoring platform. 
You analyze patient vitals and provide structured clinical insights to assist healthcare professionals.
IMPORTANT: Always clarify these are AI-assisted suggestions, not definitive diagnoses. Doctors make final decisions.
Respond ONLY in valid JSON format with no extra text.`;

  const userMessage = `Analyze this patient and provide clinical insights:

PATIENT: ${patient.name}, Age: ${new Date().getFullYear()-new Date(patient.date_of_birth).getFullYear()}, Blood Type: ${patient.blood_type}
KNOWN CONDITION: ${patient.condition}
WARD: ${patient.ward}

CURRENT VITALS:
- Heart Rate: ${hr} bpm (normal: 60-100)
- Blood Pressure: ${bp} mmHg (normal: <130)
- SpO2: ${o2}% (normal: 95-100%)
- Temperature: ${temp}°C (normal: 36.1-37.2)

VITALS TREND (last 10 readings):
${vitalsHistory.map(v=>`HR:${v.heart_rate} BP:${v.blood_pressure} O2:${v.oxygen_saturation} Temp:${v.temperature}`).join('\n')}

RECENT CLINICAL NOTES:
${recentNotes.length>0 ? recentNotes.map(n=>`${n.role} ${n.name}: ${n.content}`).join('\n') : 'No recent notes'}

Respond with this exact JSON structure:
{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_score": 0-100,
  "summary": "2-3 sentence clinical summary",
  "concerns": ["concern 1", "concern 2"],
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"],
  "vitals_analysis": {
    "heart_rate": "normal|elevated|low|critical",
    "blood_pressure": "normal|elevated|low|critical",
    "oxygen": "normal|low|critical",
    "temperature": "normal|fever|hypothermia|critical"
  },
  "suggested_tests": ["test 1", "test 2"],
  "medications_to_review": ["med 1"],
  "disclaimer": "AI-assisted suggestion only. Clinical judgment required."
}`;

  try {
    if (!process.env.ANTHROPIC_API_KEY) {
      // Demo mode — return realistic mock diagnosis
      const isAlertPatient = hr>100||hr<55||o2<93||bp>140||temp>38.5;
      const mockDiagnosis = {
        risk_level: isAlertPatient ? (hr>120||o2<90 ? 'CRITICAL' : 'HIGH') : (hr>90||bp>135 ? 'MEDIUM' : 'LOW'),
        risk_score: isAlertPatient ? (hr>120||o2<90 ? 85 : 65) : (hr>90||bp>135 ? 45 : 20),
        summary: `Patient ${patient.name} with ${patient.condition} showing ${isAlertPatient?'concerning':'stable'} vital signs. ${bp>140?'Hypertensive readings require attention. ':''}${o2<93?'Oxygen saturation below safe threshold. ':''}${temp>38.5?'Febrile state detected.':'Afebrile.'}`,
        concerns: [
          ...(hr>100?[`Tachycardia at ${hr} bpm — monitor for arrhythmia`]:[]),
          ...(hr<55?[`Bradycardia at ${hr} bpm — risk of low cardiac output`]:[]),
          ...(bp>140?[`Hypertension at ${bp} mmHg — stroke risk elevated`]:[]),
          ...(o2<93?[`Hypoxemia at ${o2}% — immediate oxygen therapy indicated`]:[]),
          ...(temp>38.5?[`Fever at ${temp}°C — infection workup recommended`]:[]),
          ...(!isAlertPatient?['Continue monitoring current treatment plan']:[]),
        ],
        recommendations: [
          bp>140 ? 'Consider antihypertensive adjustment' : 'Maintain current BP management',
          o2<93 ? 'Initiate supplemental oxygen therapy immediately' : 'Continue SpO2 monitoring',
          temp>38.5 ? 'Blood cultures and CBC — rule out sepsis' : 'Monitor temperature q4h',
          hr>100 ? '12-lead ECG recommended' : 'Routine cardiac monitoring',
        ],
        vitals_analysis: {
          heart_rate: hr>100?'elevated':hr<55?'low':'normal',
          blood_pressure: bp>140?'elevated':bp<90?'low':'normal',
          oxygen: o2<90?'critical':o2<95?'low':'normal',
          temperature: temp>39?'critical':temp>38.5?'fever':temp<36?'hypothermia':'normal',
        },
        suggested_tests: [
          ...(o2<93?['Arterial Blood Gas (ABG)','Chest X-ray']:[]),
          ...(temp>38.5?['Blood cultures x2','Complete Blood Count','CRP/Procalcitonin']:[]),
          ...(bp>150?['Renal function panel','Urinalysis']:[]),
          ...(!isAlertPatient?['Routine morning labs']:[]),
        ],
        medications_to_review: [
          ...(bp>140?['Current antihypertensives — dose review']:[]),
          ...(o2<93?['Bronchodilators if applicable']:[]),
          ...(temp>38.5?['Antipyretics — paracetamol 1g q6h']:[]),
        ],
        disclaimer: 'AI-assisted suggestion only (Demo Mode — add ANTHROPIC_API_KEY for real AI). Clinical judgment required.',
      };

      // Save to DB
      db.prepare('INSERT INTO ai_diagnoses (patient_id,user_id,vitals_snapshot,diagnosis,risk_level,recommendations,model) VALUES (?,?,?,?,?,?,?)')
        .run(req.params.id, req.user.id, JSON.stringify({hr,bp,o2,temp}), JSON.stringify(mockDiagnosis), mockDiagnosis.risk_level, JSON.stringify(mockDiagnosis.recommendations), 'demo-mode');

      audit(req.user.id, 'AI_DIAGNOSE', `AI analysis for ${patient.name} (demo) — ${mockDiagnosis.risk_level}`, req.ip);
      console.log(`🤖 AI (demo): ${patient.name} → ${mockDiagnosis.risk_level} risk`);
      return res.json({ diagnosis: mockDiagnosis, mode: 'demo', patient: patient.name });
    }

    // Real Claude AI
    const response = await callClaude([{ role:'user', content: userMessage }], systemPrompt);
    const clean = response.replace(/```json|```/g,'').trim();
    const diagnosis = JSON.parse(clean);

    db.prepare('INSERT INTO ai_diagnoses (patient_id,user_id,vitals_snapshot,diagnosis,risk_level,recommendations) VALUES (?,?,?,?,?,?)')
      .run(req.params.id, req.user.id, JSON.stringify({hr,bp,o2,temp}), JSON.stringify(diagnosis), diagnosis.risk_level, JSON.stringify(diagnosis.recommendations));

    audit(req.user.id, 'AI_DIAGNOSE', `AI analysis for ${patient.name} — ${diagnosis.risk_level}`, req.ip);
    console.log(`🤖 AI (Claude): ${patient.name} → ${diagnosis.risk_level} risk (score: ${diagnosis.risk_score})`);
    res.json({ diagnosis, mode: 'claude', patient: patient.name });

  } catch(e) {
    console.error('AI error:', e.message);
    res.status(500).json({ error: `AI analysis failed: ${e.message}` });
  }
});

// Get AI diagnosis history for a patient
app.get('/ai/history/:id', authenticate, requirePerm('view_ai'), (req, res) => {
  const history = db.prepare(`
    SELECT a.*, u.name as requested_by FROM ai_diagnoses a
    JOIN users u ON a.user_id=u.id
    WHERE a.patient_id=? ORDER BY a.created_at DESC LIMIT 10
  `).all(req.params.id);
  res.json({ history: history.map(h=>({...h, diagnosis:JSON.parse(h.diagnosis), recommendations:JSON.parse(h.recommendations)})) });
});

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user||!bcrypt.compareSync(password,user.password_hash)) return res.status(401).json({ error:'Invalid credentials.' });
  const token = jwt.sign({ id:user.id,username:user.username,role:user.role,name:user.name }, JWT_SECRET, { expiresIn:'8h' });
  audit(user.id,'LOGIN',`${user.name} logged in`,req.ip);
  console.log(`✅ Login: ${user.name} (${user.role})`);
  res.json({ token, user:{id:user.id,name:user.name,role:user.role,department:user.department,permissions:ROLE_PERMISSIONS[user.role]||[]} });
});

app.post('/auth/logout', authenticate, (req, res) => {
  audit(req.user.id,'LOGOUT',`${req.user.name} logged out`,req.ip);
  res.json({ message:'Logged out.' });
});

// ── PATIENTS ──────────────────────────────────────────────────────────────────
app.get('/patients', authenticate, requirePerm('view_patients'), (req, res) => {
  const patients = db.prepare(`
    SELECT p.*, v.heart_rate,v.blood_pressure,v.oxygen_saturation,v.temperature,v.source
    FROM patients p
    LEFT JOIN vitals v ON v.id=(SELECT id FROM vitals WHERE patient_id=p.id ORDER BY recorded_at DESC LIMIT 1)
    WHERE p.status='active' ORDER BY p.ward,p.room
  `).all();
  res.json({ patients });
});

app.delete('/patients/:id', authenticate, requirePerm('discharge'), (req, res) => {
  const p = db.prepare('SELECT * FROM patients WHERE id=?').get(req.params.id);
  if (!p) return res.status(404).json({ error:'Not found.' });
  db.prepare("UPDATE patients SET status='discharged',discharged_at=CURRENT_TIMESTAMP WHERE id=?").run(req.params.id);
  audit(req.user.id,'DISCHARGE',`Discharged ${p.name}`,req.ip);
  console.log(`🏥 Discharged: ${p.name}`);
  res.json({ message:`${p.name} discharged.` });
});

// ── SIMULATOR ─────────────────────────────────────────────────────────────────
app.get('/simulator', authenticate, (req, res) => {
  const patients = db.prepare("SELECT * FROM patients WHERE status='active'").all();
  res.json({ results: patients.map(simulatePatient), timestamp: new Date().toISOString() });
});

app.get('/simulator/:id', authenticate, (req, res) => {
  const patient = db.prepare('SELECT * FROM patients WHERE id=?').get(req.params.id);
  if (!patient) return res.status(404).json({ error:'Not found.' });
  res.json({ ...simulatePatient(patient), source:'LiveSense Medical Device Simulator v1.0' });
});

// ── FHIR ──────────────────────────────────────────────────────────────────────
app.get('/fhir/search', authenticate, async (req, res) => {
  try {
    const { name='', count=5 } = req.query;
    const query = name ? `?name=${encodeURIComponent(name)}&_count=${count}` : `?_count=${count}&_sort=-_lastUpdated`;
    const bundle = await fetchFHIR(`/Patient${query}`);
    const patients = (bundle.entry||[]).filter(e=>e.resource?.resourceType==='Patient').map(e=>parseFHIRPatient(e.resource));
    res.json({ patients, total: bundle.total||patients.length });
  } catch(e) { res.status(503).json({ error:'FHIR unavailable.' }); }
});

app.get('/fhir/patient/:id', authenticate, async (req, res) => {
  try {
    const resource = await fetchFHIR(`/Patient/${req.params.id}`);
    audit(req.user.id,'FHIR_FETCH',`FHIR patient ${req.params.id}`,req.ip);
    res.json({ fhir: parseFHIRPatient(resource), raw: resource });
  } catch(e) { res.status(503).json({ error:'FHIR unavailable.' }); }
});

// ── NOTES ─────────────────────────────────────────────────────────────────────
app.get('/patients/:id/notes', authenticate, requirePerm('view_patients'), (req, res) => {
  const notes = db.prepare(`SELECT n.*,u.name as author,u.role as author_role FROM notes n JOIN users u ON n.user_id=u.id WHERE n.patient_id=? ORDER BY n.created_at DESC`).all(req.params.id);
  res.json({ notes });
});

app.post('/patients/:id/notes', authenticate, requirePerm('add_notes'), (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error:'Content required.' });
  const result = db.prepare('INSERT INTO notes (patient_id,user_id,content) VALUES (?,?,?)').run(req.params.id,req.user.id,content.trim());
  const p = db.prepare('SELECT name FROM patients WHERE id=?').get(req.params.id);
  audit(req.user.id,'ADD_NOTE',`Note for ${p?.name}`,req.ip);
  console.log(`📋 Note: ${req.user.name} → ${p?.name}`);
  res.json({ id:result.lastInsertRowid, message:'Saved.' });
});

// ── USERS (Admin) ─────────────────────────────────────────────────────────────
app.get('/users', authenticate, requirePerm('manage_users'), (req, res) => {
  const users = db.prepare('SELECT id,username,name,role,department,created_at FROM users').all();
  res.json({ users });
});

// ── AUDIT + STATS ─────────────────────────────────────────────────────────────
app.get('/audit', authenticate, requirePerm('view_audit'), (req, res) => {
  const logs = db.prepare(`SELECT a.*,u.name as user_name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 100`).all();
  res.json({ logs });
});

app.get('/stats', authenticate, (req, res) => {
  res.json({ stats: {
    active_patients:  db.prepare("SELECT COUNT(*) as c FROM patients WHERE status='active'").get().c,
    discharged:       db.prepare("SELECT COUNT(*) as c FROM patients WHERE status='discharged'").get().c,
    total_vitals:     db.prepare("SELECT COUNT(*) as c FROM vitals").get().c,
    vitals_today:     db.prepare("SELECT COUNT(*) as c FROM vitals WHERE date(recorded_at)=date('now')").get().c,
    total_notes:      db.prepare("SELECT COUNT(*) as c FROM notes").get().c,
    ai_analyses:      db.prepare("SELECT COUNT(*) as c FROM ai_diagnoses").get().c,
    ai_today:         db.prepare("SELECT COUNT(*) as c FROM ai_diagnoses WHERE date(created_at)=date('now')").get().c,
    total_users:      db.prepare("SELECT COUNT(*) as c FROM users").get().c,
  }});
});

app.get('/', (req,res) => res.redirect('/landing.html'));


app.use('/mobile', require('express').static(require('path').join(__dirname, 'mobile')));


app.use('/mobile', express.static(require('path').join(__dirname, 'mobile')));
app.listen(process.env.PORT || 3001, () => { console.log('\n?? Live Sense AI v6.0 � http://localhost:3001\n?? PWA: http://localhost:3001/mobile'); });
app.use(require('express').static(__dirname));
