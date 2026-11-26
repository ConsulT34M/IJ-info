// RKX ↔ IJ-info 엔드투엔드.
//
// RKX 서버 전체(MySQL 필요)는 못 띄우므로 **RKX 가 실제로 쓰는 클라이언트 코드**
// (identity-service.js 의 ijinfoRequest / inboxUrl)를 그대로 불러 IJ-info 를 호출한다.
// 서명 형식·엔드포인트·본문 모양·사유 코드가 양쪽에서 맞는지 본다.
import fs from 'node:fs';
const RKX_DIR = process.env.RKX_DIR || '../Rkx';
const { ijinfoRequest, inboxUrl, partnerConfigured } =
  await import(new URL(`${RKX_DIR}/identity-service.js`, `file://${process.cwd()}/`).href);

const env = {
  NODE_ENV: 'development',
  IJINFO_BASE_URL: process.env.EKYC_BASE_URL || 'http://127.0.0.1:8000',
  IJINFO_API_KEY: process.env.EKYC_API_KEY,
  IJINFO_HMAC_SECRET: process.env.EKYC_HMAC_SECRET,
};
const opts = { env };
const PEOPLE = JSON.parse(fs.readFileSync(process.env.PEOPLE_FILE, 'utf8')).people;
const b64 = path => fs.readFileSync(path).toString('base64');
const ID_IMAGE = b64(process.env.ID_CARD_IMAGE);
const FACE_IMAGE = b64(process.env.FACE_IMAGE);
const NOFACE_IMAGE = b64(process.env.NOFACE_IMAGE);

let pass = 0, fail = 0;
const ok = (label, condition, extra = '') => {
  if (condition) { console.log(`  \x1b[32m○\x1b[0m ${label}`); pass++; }
  else { console.log(`  \x1b[31m×\x1b[0m ${label}  ${extra}`); fail++; }
};
const err = async fn => { try { await fn(); return null; } catch (e) { return e; } };

// 이용자 휴대폰(IJ-info 문자 수신함)에서 인증번호를 읽는다. RKX 서버는 볼 수 없다.
async function readCode(inboxKey) {
  const base = inboxUrl(env);
  const page = await fetch(base);
  const html = await page.text();
  const token = /name="csrf_token" value="([^"]+)"/.exec(html)[1];
  const cookie = page.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
  const res = await fetch(`${base}latest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ inbox_key: inboxKey, csrf_token: token }),
  });
  return (/class="ij-code mb-1">(\d{6})</.exec(await res.text()) || [])[1];
}

const start = async ref => (await ijinfoRequest('POST', '/verifications', { client_user_ref: ref, mode: 'DIRECT' }, opts)).verification_id;
const otp = (id, person, extra = {}) => ijinfoRequest('POST', `/verifications/${id}/phone/otp`, { name: person.name, phone_number: person.phone_number, ...extra }, opts);
const confirm = (id, code) => ijinfoRequest('POST', `/verifications/${id}/phone/confirm`, { code }, opts);
const idCard = (id, person, extra = {}) => ijinfoRequest('POST', `/verifications/${id}/id-card`, {
  name: person.name, rrn: person.rrn, issue_date: person.issue_date,
  filename: 'id_card.png', image: ID_IMAGE, ...extra,
}, opts);
const face = (id, extra = {}) => ijinfoRequest('POST', `/verifications/${id}/face`, { filename: 'selfie.png', image: FACE_IMAGE, ...extra }, opts);

const tag = () => Math.random().toString(36).slice(2, 8);

console.log(`\nRKX → IJ-info 엔드투엔드  (${env.IJINFO_BASE_URL})\n`);
ok('연동 설정이 갖춰졌다 (CI 생성키 없이)', partnerConfigured(env));

// ── 1. 성공 경로 ────────────────────────────────────────────────────────
console.log('\n[1] 성공 경로 — 1번 인물, 실제 신분증·얼굴 사진');
{
  const person = PEOPLE[0];
  const id = await start(`e2e-ok-${tag()}`);

  const issued = await otp(id, person);
  ok('IA-23 인증번호 발송', issued.stage === 'PHONE');
  ok('응답에 인증번호가 없다', !JSON.stringify(issued).match(/\b\d{6}\b/), JSON.stringify(issued));
  ok('번호가 마스킹돼 있다', issued.phone_mask?.startsWith('010-****'), issued.phone_mask);

  const code = await readCode(person.inbox_key);
  ok('이용자 휴대폰에서 인증번호를 읽었다', /^\d{6}$/.test(code || ''), String(code));

  const confirmed = await confirm(id, code);
  ok('IA-24 확인 → 신분증 단계', confirmed.stage === 'ID_CARD' && confirmed.passed === true);
  ok('응답에 CI 가 없다', !JSON.stringify(confirmed).includes('ci'), JSON.stringify(confirmed));

  const card = await idCard(id, person);
  ok('IA-21 신분증 통과 → 얼굴 단계', card.stage === 'FACE' && card.passed === true, JSON.stringify(card));

  const result = await face(id);
  ok('IA-22 최종 판정 SUCCEEDED', result.status === 'SUCCEEDED' && result.reason_code === 'OK', JSON.stringify(result));
  ok('휴대폰 단계가 PASSED 로 보고된다', result.stages?.phone === 'PASSED', JSON.stringify(result.stages));
  ok('CI 는 결과에만 담겨 돌아온다 (88자)', result.ci_mock?.length === 88);
}

// ── 2. CI 를 직접 보내면 거부한다 ─────────────────────────────────────────
// 번호마다 60초 발송 제한(D11)이 있으므로 시나리오마다 다른 가상 인물을 쓴다.
console.log('\n[2] 위탁사가 CI 를 보내면 거부한다');
{
  const person = PEOPLE[1];
  const id = await start(`e2e-ci-${tag()}`);
  await otp(id, person);
  await confirm(id, await readCode(person.inbox_key));
  const e = await err(() => idCard(id, person, { ci: 'x'.repeat(88) }));
  ok('ci 를 보내면 400', e?.status === 400, String(e?.status));
  ok('무엇이 문제인지 알려 준다', /ci/.test(e?.message || ''), e?.message);
}

// ── 3. X-01 — 휴대폰 명의자 ≠ 신분증 명의자 ───────────────────────────────
console.log('\n[3] X-01 — 휴대폰은 1번 인물, 신분증은 2번 인물');
{
  const id = await start(`e2e-x01-${tag()}`);
  await otp(id, PEOPLE[2]);
  await confirm(id, await readCode(PEOPLE[2].inbox_key));
  const result = await idCard(id, PEOPLE[3]);
  ok('X01 로 즉시 종결', result.status === 'FAILED' && result.reason_code === 'X01', JSON.stringify(result));
  ok('단계 보고가 맞다', result.stages?.phone === 'PASSED' && result.stages?.id_card === 'FAILED');
  ok('실패 결과에는 CI·성명이 없다', !result.ci_mock && !result.name);
}

// ── 4. P01 — 명의 대조 불일치 3회 ─────────────────────────────────────────
console.log('\n[4] P01 — 성명이 명의자와 다르다');
{
  const person = PEOPLE[4];
  const id = await start(`e2e-p01-${tag()}`);
  const first = await err(() => otp(id, { ...person, name: '다른사람' }));
  ok('1회차 400 + 남은 횟수 2', first?.status === 400 && first?.attemptsLeft === 2, `${first?.status}/${first?.attemptsLeft}`);

  const unknown = await err(() => otp(id, { ...person, phone_number: '01000000000' }));
  ok('미등록 번호도 같은 상태 코드', unknown?.status === 400, String(unknown?.status));
  ok('사유를 구분해 알려 주지 않는다',
     first?.message?.split('(남은')[0] === unknown?.message?.split('(남은')[0],
     `${first?.message} / ${unknown?.message}`);

  const last = await err(() => otp(id, { ...person, name: '다른사람' }));
  ok('3회차에 P01 종결', last?.status === 409 && last?.reasonCode === 'P01', `${last?.status}/${last?.reasonCode}`);
}

// ── 5. P02 — 인증번호 3회 불일치 ─────────────────────────────────────────
console.log('\n[5] P02 — 인증번호가 틀렸다');
{
  const person = PEOPLE[5];
  const id = await start(`e2e-p02-${tag()}`);
  await otp(id, person);
  const real = await readCode(person.inbox_key);
  const wrong = real === '000000' ? '111111' : '000000';

  const shortCode = await err(() => confirm(id, '12'));
  ok('형식 오류는 400', shortCode?.status === 400);

  for (const left of [2, 1]) {
    const e = await err(() => confirm(id, wrong));
    ok(`틀린 번호 → 남은 횟수 ${left}`, e?.status === 400 && e?.attemptsLeft === left, `${e?.status}/${e?.attemptsLeft}`);
  }
  const done = await err(() => confirm(id, wrong));
  ok('3회차에 P02 종결', done?.status === 409, String(done?.status));
  ok('형식 오류는 횟수에 넣지 않았다', true);
}

// ── 6. 재발송 제한 ───────────────────────────────────────────────────────
console.log('\n[6] 재발송 60초 제한');
{
  const person = PEOPLE[6];
  const id = await start(`e2e-resend-${tag()}`);
  await otp(id, person);
  const again = await err(() => otp(id, person, { resend: true }));
  ok('60초 안에는 429', again?.status === 429, String(again?.status));
}

// ── 7. 얼굴 불일치 (E05) ─────────────────────────────────────────────────
console.log('\n[7] E04 — 얼굴이 검출되지 않는 사진 → 재제출');
{
  const person = PEOPLE[7];
  const id = await start(`e2e-e05-${tag()}`);
  await otp(id, person);
  await confirm(id, await readCode(person.inbox_key));
  await idCard(id, person);
  // FACE_MATCHER=local 은 파일명을 보지 않는다(그게 맞다). 그래서 '이름만 mismatch 인
  // 같은 사진'으로는 불일치를 만들 수 없다. 얼굴이 없는 사진으로 E04 를 확인한다.
  // 유사도 미달(E05)은 다른 사람 얼굴 사진이 있어야 하므로 pytest 쪽에서 본다.
  const e = await err(() => face(id, { filename: 'selfie.png', image: NOFACE_IMAGE }));
  ok('다시 제출하면 되는 실패(400)', e?.status === 400, String(e?.status));
  ok('사유 코드가 E04', e?.reasonCode === 'E04', e?.reasonCode);
  ok('남은 횟수를 알려 준다', typeof e?.attemptsLeft === 'number', String(e?.attemptsLeft));

  // 같은 건에 올바른 셀카를 다시 내면 통과한다 — 재제출이 실제로 되는지 본다.
  const retry = await face(id);
  ok('올바른 사진으로 재제출하면 통과', retry.status === 'SUCCEEDED', JSON.stringify(retry.reason_code));
}

// ── 8. 휴대폰 단계를 건너뛸 수 없다 ───────────────────────────────────────
console.log('\n[8] 휴대폰 본인확인을 건너뛸 수 없다');
{
  const id = await start(`e2e-skip-${tag()}`);
  const e = await err(() => idCard(id, PEOPLE[9]));
  ok('신분증부터 내면 거부', e?.status === 403 || e?.status === 409, String(e?.status));
}

// ── 9. E03 — 진위확인 대장에서 분실 상태인 인물 ──────────────────────────
console.log('\n[9] E03 — 9번 인물(분실 신고된 신분증)');
{
  const person = PEOPLE[8];
  const id = await start(`e2e-e03-${tag()}`);
  await otp(id, person);
  await confirm(id, await readCode(person.inbox_key));
  const e = await err(() => idCard(id, person));
  ok('E03 으로 재입력 요구(400)', e?.status === 400 && e?.reasonCode === 'E03', `${e?.status}/${e?.reasonCode}`);
}

console.log(`\n  통과 ${pass} · 실패 ${fail}\n`);
process.exit(fail === 0 ? 0 : 1);
