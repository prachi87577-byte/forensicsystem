const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Stage 2: AI message analysis (rule-based classifier) ----------
const RULES = {
  'Threat / Violence': ['kill', 'hurt', 'attack', 'weapon', 'revenge', 'threat'],
  'Harassment': ['idiot', 'stupid', 'loser', 'hate you', 'shut up'],
  'Substance Related': ['drug', 'pill', 'dose', 'overdose', 'poison', 'tablet', 'sample'],
  'Suspicious Activity': ['delete', 'erase', 'hide', 'destroy', 'secret', "don't tell"]
};

function classify(text) {
  const t = text.toLowerCase();
  let best = { category: 'Normal', score: 0, keywords: [] };
  for (const [category, words] of Object.entries(RULES)) {
    const hits = words.filter(w => t.includes(w));
    if (hits.length > best.score) best = { category, score: hits.length, keywords: hits };
  }
  return best;
}

// ---------- Stage 3: digital forensic analysis ----------
const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');

function detectType(buf) {
  if (buf.slice(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) return 'image/jpeg';
  if (buf.slice(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) return 'image/png';
  return null;
}

function parseCSV(text) {
  const rows = text.trim().split(/\r?\n/).map(l => l.split(',').map(c => c.trim()));
  const head = rows.shift().map(h => h.toLowerCase());
  return rows.map(r => Object.fromEntries(head.map((h, i) => [h, r[i] || ''])));
}

// ---------- Pipeline ----------
app.post('/api/analyze', upload.array('files'), (req, res) => {
  try {
    const now = new Date().toISOString();
    const messages = [];
    const lab = [];
    const files = [];

    // Stage 1: input evidence
    (req.body.chat || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)
      .forEach(text => messages.push({ source: 'chat-input', text }));

    for (const f of req.files || []) {
      const info = {
        name: f.originalname,
        declaredType: f.mimetype,
        size: f.size,
        sha256: sha256(f.buffer),
        receivedAt: now,
        kind: 'other',
        note: ''
      };
      const sig = detectType(f.buffer);
      if (f.mimetype.startsWith('image/')) {
        info.kind = 'image';
        info.detectedType = sig || 'unknown';
        info.note = sig === f.mimetype ? 'Signature matches declared type' : 'Signature does not match declared type';
      } else if (f.originalname.toLowerCase().endsWith('.csv')) {
        const rows = parseCSV(f.buffer.toString('utf8'));
        if (rows.length && 'sample_id' in rows[0]) {
          info.kind = 'toxicology-csv';
          rows.forEach(r => lab.push({ ...r, file: f.originalname }));
        } else if (rows.length && 'message' in rows[0]) {
          info.kind = 'chat-csv';
          rows.forEach(r => messages.push({ source: f.originalname, sender: r.sender, time: r.time, text: r.message }));
        }
        info.note = `${rows.length} records`;
      }
      files.push(info);
    }

    // Stage 2: classify
    const analysed = messages.map(m => ({ ...m, ...classify(m.text) }));
    const counts = {};
    analysed.forEach(m => (counts[m.category] = (counts[m.category] || 0) + 1));

    // Stage 4: toxicology matching (fictional sample IDs, e.g. S-101)
    const matches = [];
    const matchedIds = new Set();
    analysed.forEach(m => {
      (m.text.match(/\b[A-Za-z]{1,3}-?\d{2,5}\b/g) || []).forEach(id => {
        const rec = lab.find(l => l.sample_id.toLowerCase() === id.toLowerCase());
        if (rec) {
          matchedIds.add(rec.sample_id.toLowerCase());
          matches.push({ sampleId: rec.sample_id, message: m.text, substance: rec.substance, result: rec.result, date: rec.date });
        }
      });
    });
    const unmatched = lab.filter(l => !matchedIds.has(l.sample_id.toLowerCase())).map(l => l.sample_id);

    // Stage 5: report
    const report = {
      caseId: 'CASE-' + Date.now().toString(36).toUpperCase(),
      generatedAt: now,
      summary: {
        messages: analysed.length,
        files: files.length,
        flagged: analysed.filter(m => m.category !== 'Normal').length,
        labRecords: lab.length,
        linkedSamples: matches.length
      },
      categoryCounts: counts,
      evidence: files,
      messages: analysed,
      toxicologyMatches: matches,
      unmatchedSamples: unmatched,
      limitations: [
        'All data is simulated; sample IDs and lab findings are fictional.',
        'Classification is keyword-based and may produce false positives or negatives.',
        'Hashes prove file integrity from upload time only, not authenticity of origin.',
        'Findings require review by a qualified human examiner.'
      ]
    };
    report.reportSha256 = sha256(Buffer.from(JSON.stringify(report)));
    res.json(report);
  } catch (e) {
    res.status(400).json({ error: 'Analysis failed: ' + e.message });
  }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) app.listen(PORT);
module.exports = app;
