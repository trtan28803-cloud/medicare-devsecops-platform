'use strict';
const $ = id => document.getElementById(id);
let me = null, patients = [], usersList = [], auditList = [], doctorsDirectory = [], selected = null, isCreatingRecord = false;
let currentWeekMonday = getMonday(new Date());

const roleLabels = {
  admin: 'Quản trị viên hệ thống',
  doctor: 'Bác sĩ điều trị',
  nurse: 'Điều dưỡng / Y tá',
  patient: 'Bệnh nhân'
};

function notify(message, error = false) {
  const el = $('notice');
  el.textContent = message;
  el.classList.toggle('error', error);
  el.hidden = false;
}

function hideNotice() {
  $('notice').hidden = true;
}

async function api(path, method = 'GET', body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (me && me.csrf) headers['X-CSRF-Token'] = me.csrf;
  const response = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  let result = {};
  try {
    result = await response.json();
  } catch (_) {}
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/login') {
      me = null;
      showLogin();
    }
    throw new Error(result.error || 'Không thể hoàn tất thao tác.');
  }
  return result;
}

function cell(row, text, className = '') {
  const td = document.createElement('td');
  if (className) td.className = className;
  td.textContent = text ?? '';
  row.append(td);
  return td;
}

const ALL_PANELS = [
  'loginPanel', 'workspace', 'schedulePanel', 'profilePanel',
  'appointmentsPanel', 'usersPanel', 'revisionsPanel', 'auditPanel'
];
const ALL_NAVS = [
  'patientsNav', 'scheduleNav', 'profileNav', 'appointmentsNav',
  'usersNav', 'revisionsNav', 'auditNav'
];

// 0. Điều khiển Sidebar
function updateSidebarToggleLabel() {
  const isMobile = window.innerWidth <= 960;
  const isHidden = isMobile
    ? !document.body.classList.contains('sidebar-mobile-open')
    : document.body.classList.contains('sidebar-collapsed');
  if ($('toggleSidebarText')) {
    $('toggleSidebarText').textContent = isHidden ? 'Hiện danh mục' : 'Ẩn danh mục';
  }
  if ($('sidebarBackdrop')) {
    $('sidebarBackdrop').hidden = !(isMobile && document.body.classList.contains('sidebar-mobile-open'));
  }
}

function toggleSidebar() {
  if (window.innerWidth <= 960) {
    document.body.classList.toggle('sidebar-mobile-open');
  } else {
    const collapsed = document.body.classList.toggle('sidebar-collapsed');
    try {
      localStorage.setItem('medicare_sidebar_collapsed', collapsed ? '1' : '0');
    } catch (_) {}
  }
  updateSidebarToggleLabel();
}

function initSidebarState() {
  try {
    if (localStorage.getItem('medicare_sidebar_collapsed') === '1') {
      document.body.classList.add('sidebar-collapsed');
    }
  } catch (_) {}
  updateSidebarToggleLabel();
}

if ($('toggleSidebarBtn')) $('toggleSidebarBtn').onclick = toggleSidebar;
if ($('collapseSidebarBtn')) $('collapseSidebarBtn').onclick = toggleSidebar;
if ($('sidebarBackdrop')) {
  $('sidebarBackdrop').onclick = () => {
    document.body.classList.remove('sidebar-mobile-open');
    updateSidebarToggleLabel();
  };
}
window.addEventListener('resize', updateSidebarToggleLabel);
initSidebarState();

function tab(panelId) {
  ALL_PANELS.forEach(id => { if ($(id)) $(id).hidden = (id !== panelId); });
  const navMap = {
    workspace: 'patientsNav',
    schedulePanel: 'scheduleNav',
    profilePanel: 'profileNav',
    appointmentsPanel: 'appointmentsNav',
    usersPanel: 'usersNav',
    revisionsPanel: 'revisionsNav',
    auditPanel: 'auditNav'
  };
  ALL_NAVS.forEach(id => { if ($(id)) $(id).classList.toggle('active', navMap[panelId] === id); });
  const titleMap = {
    workspace: (me && me.role === 'patient') ? 'Bệnh án cá nhân' : 'Hồ sơ bệnh án',
    schedulePanel: (me && me.role === 'doctor') ? 'Lịch trình & Xác nhận lịch hẹn' : 'Lịch trình khám bệnh của Bác sĩ',
    profilePanel: 'Thông tin cá nhân',
    appointmentsPanel: 'Đặt lịch khám bệnh',
    usersPanel: 'Quản lý tài khoản',
    revisionsPanel: 'Lịch sử chỉnh sửa hồ sơ',
    auditPanel: 'Nhật ký hệ thống'
  };
  if ($('pageTitle')) $('pageTitle').textContent = titleMap[panelId] || 'Hệ thống MediCare';
  if (window.innerWidth <= 960) {
    document.body.classList.remove('sidebar-mobile-open');
    updateSidebarToggleLabel();
  }
}

function showLogin() {
  document.body.classList.add('logged-out');
  document.body.classList.remove('sidebar-mobile-open');
  $('sidebar').hidden = true;
  if ($('sidebarBackdrop')) $('sidebarBackdrop').hidden = true;
  $('topHeader').hidden = true;
  ALL_NAVS.forEach(id => { if ($(id)) $(id).hidden = true; });
  ALL_PANELS.forEach(id => { if ($(id)) $(id).hidden = (id !== 'loginPanel'); });
  $('identity').replaceChildren();
}

// 1. Khôi phục mật khẩu qua SĐT & OTP
function showForgotNotice(msg, isError = false) {
  const el = $('forgotNotice');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  el.hidden = false;
}

$('forgotPwdLink').onclick = () => {
  $('forgotNotice').hidden = true;
  $('forgotRequestForm').reset();
  $('forgotResetForm').reset();
  $('forgotResetForm').hidden = true;
  $('forgotDialog').showModal();
};

$('closeForgotDialog').onclick = () => $('forgotDialog').close();

$('forgotRequestForm').onsubmit = async e => {
  e.preventDefault();
  try {
    const res = await api('/api/forgot-password/request-otp', 'POST', {
      username: $('fpUsername').value.trim(),
      phone: $('fpPhone').value.trim()
    });
    const otpHint = (res.otp_code || res.otp_demo_code) ? ` (Mã OTP xác thực: ${(res.otp_code || res.otp_demo_code)})` : '';
    showForgotNotice((res.message || 'Đã gửi mã OTP.') + otpHint, false);
    if ((res.otp_code || res.otp_demo_code)) {
      $('fpOtp').value = (res.otp_code || res.otp_demo_code);
    }
    $('forgotResetForm').hidden = false;
  } catch (err) {
    showForgotNotice(err.message, true);
  }
};

$('forgotResetForm').onsubmit = async e => {
  e.preventDefault();
  try {
    const res = await api('/api/forgot-password/reset', 'POST', {
      username: $('fpUsername').value.trim(),
      phone: $('fpPhone').value.trim(),
      otp: $('fpOtp').value.trim(),
      new_password: $('fpNewPassword').value
    });
    $('forgotDialog').close();
    $('username').value = $('fpUsername').value.trim();
    $('password').value = '';
    notify(res.message || 'Đặt lại mật khẩu thành công. Vui lòng đăng nhập.');
  } catch (err) {
    showForgotNotice(err.message, true);
  }
};

// 2. Danh bạ Khoa & Bác sĩ
async function loadDoctorsDirectory() {
  try {
    const data = await api('/api/doctors');
    doctorsDirectory = data.doctors || [];
    updateCascadingDoctorsDropdown();
    populateScheduleDoctorFilter();
  } catch (_) {
    doctorsDirectory = [];
  }
}

function updateCascadingDoctorsDropdown() {
  const deptSelect = $('apptDept');
  const docSelect = $('apptDoctor');
  if (!deptSelect || !docSelect) return;
  const selectedDept = deptSelect.value;
  docSelect.replaceChildren();

  const emptyOpt = document.createElement('option');
  emptyOpt.value = '';
  emptyOpt.textContent = '-- Để trống (Bác sĩ thuộc khoa tiếp nhận) --';
  docSelect.append(emptyOpt);

  const matchingDocs = doctorsDirectory.filter(d => d.department === selectedDept);
  for (const d of matchingDocs) {
    const opt = document.createElement('option');
    opt.value = d.username;
    opt.textContent = `${d.full_name} (${d.department})`;
    docSelect.append(opt);
  }
}

if ($('apptDept')) {
  $('apptDept').onchange = updateCascadingDoctorsDropdown;
}

function populateScheduleDoctorFilter() {
  const sel = $('scheduleDocFilter');
  if (!sel) return;
  const currentVal = sel.value;
  sel.replaceChildren();
  const allOpt = document.createElement('option');
  allOpt.value = 'ALL';
  allOpt.textContent = 'Tất cả bác sĩ';
  sel.append(allOpt);
  for (const d of doctorsDirectory) {
    const opt = document.createElement('option');
    opt.value = d.username;
    opt.textContent = `${d.full_name} — Khoa ${d.department}`;
    sel.append(opt);
  }
  if (me && me.role === 'doctor') {
    sel.value = me.username;
  } else if (currentVal) {
    sel.value = currentVal;
  }
}

// 3. Hồ sơ bệnh án
function renderRecords() {
  const q = ($('search').value || '').trim().toLocaleLowerCase('vi');
  $('records').replaceChildren();
  const list = patients.filter(p =>
    [p.id, p.name, p.diagnosis, p.branch, p.attending_doctor, p.treatment_plan].join(' ').toLocaleLowerCase('vi').includes(q)
  );
  for (const p of list) {
    const row = document.createElement('tr');
    cell(row, p.id, 'text-center');
    cell(row, p.name);
    cell(row, String(p.birth), 'text-center');
    const branchTd = cell(row, '', 'text-center');
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = p.branch;
    branchTd.append(badge);
    cell(row, p.attending_doctor || '—');
    cell(row, p.diagnosis);
    cell(row, (p.updated || '').replace('T', ' ').replace('Z', ''), 'text-center');
    const actionTd = cell(row, '', 'text-center');
    const btn = document.createElement('button');
    btn.className = 'sm';
    btn.textContent = (me && me.role === 'doctor') ? 'Chi tiết / Sửa' : 'Xem chi tiết';
    btn.onclick = () => openRecordDialog(p);
    actionTd.append(btn);
    $('records').append(row);
  }
  if (!list.length) {
    const row = document.createElement('tr');
    const td = cell(row, 'Không có hồ sơ bệnh án phù hợp.', 'text-center');
    td.colSpan = 8;
    $('records').append(row);
  }
}

async function refreshRecords() {
  if (!me || me.role === 'admin') return;
  patients = await api('/api/patients');
  renderRecords();
}

function openRecordDialog(p) {
  isCreatingRecord = false;
  selected = p;
  $('newRecordFields').hidden = true;
  $('recordIdLabel').textContent = p.id;
  $('recordName').textContent = p.name;
  $('recordMeta').textContent = `Năm sinh: ${p.birth} · Cơ sở: ${p.branch} · SĐT: ${p.phone || '—'}`;
  $('attendingDoctor').value = p.attending_doctor || '';
  $('diagnosis').value = p.diagnosis || '';
  $('treatmentPlan').value = p.treatment_plan || '';
  $('note').value = p.note || '';
  $('updated').textContent = `Cập nhật gần nhất: ${(p.updated || '').replace('T', ' ').replace('Z', '')}`;

  const canEdit = me && me.role === 'doctor';
  const canDelete = me && me.role === 'doctor';
  $('attendingDoctor').readOnly = !canEdit;
  $('diagnosis').readOnly = !canEdit;
  $('treatmentPlan').readOnly = !canEdit;
  $('note').readOnly = !canEdit;
  $('saveBtn').hidden = !canEdit;
  $('deleteBtn').hidden = !canDelete;
  $('recordDialog').showModal();
}

function openCreateRecordDialog() {
  isCreatingRecord = true;
  selected = null;
  $('newRecordFields').hidden = false;
  $('recordIdLabel').textContent = 'THÊM HỒ SƠ MỚI';
  $('recordName').textContent = 'Thông tin bệnh án';
  $('recordMeta').textContent = '';
  $('recIdInput').value = 'DEMO-0' + String(patients.length + 1).padStart(2, '0');
  $('recFullNameInput').value = '';
  $('recBirthInput').value = '1990';
  $('attendingDoctor').value = (me && me.full_name) ? me.full_name : '';
  $('diagnosis').value = '';
  $('treatmentPlan').value = '';
  $('note').value = '';
  $('updated').textContent = '';

  $('attendingDoctor').readOnly = false;
  $('diagnosis').readOnly = false;
  $('treatmentPlan').readOnly = false;
  $('note').readOnly = false;
  $('saveBtn').hidden = false;
  $('deleteBtn').hidden = true;
  $('recordDialog').showModal();
}

$('recordForm').onsubmit = async e => {
  e.preventDefault();
  try {
    if (isCreatingRecord) {
      const payload = {
        id: $('recIdInput').value.trim(),
        site: $('recSiteInput').value,
        full_name: $('recFullNameInput').value.trim(),
        birth_year: Number($('recBirthInput').value),
        attending_doctor: $('attendingDoctor').value.trim(),
        diagnosis: $('diagnosis').value.trim(),
        treatment_plan: $('treatmentPlan').value.trim(),
        note: $('note').value.trim()
      };
      await api('/api/patients', 'POST', payload);
      $('recordDialog').close();
      await refreshRecords();
      notify(`Đã tạo hồ sơ bệnh án ${payload.id}.`);
    } else if (selected) {
      const payload = {
        attending_doctor: $('attendingDoctor').value.trim(),
        diagnosis: $('diagnosis').value.trim(),
        treatment_plan: $('treatmentPlan').value.trim(),
        note: $('note').value.trim()
      };
      await api('/api/patients/' + selected.id, 'PUT', payload);
      $('recordDialog').close();
      await refreshRecords();
      notify(`Đã lưu cập nhật hồ sơ ${selected.id}.`);
    }
  } catch (err) {
    notify(err.message, true);
  }
};

$('deleteBtn').onclick = async () => {
  if (!selected) return;
  try {
    await api('/api/patients/' + selected.id, 'DELETE', {});
    $('recordDialog').close();
    await refreshRecords();
    notify(`Đã xóa hồ sơ ${selected.id}.`);
  } catch (err) {
    notify(err.message, true);
  }
};

$('newRecordBtn').onclick = openCreateRecordDialog;
$('closeDialog').onclick = () => $('recordDialog').close();
$('search').oninput = renderRecords;
$('search').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); renderRecords(); } };
if ($('searchBtn')) $('searchBtn').onclick = renderRecords;
$('refreshBtn').onclick = () => refreshRecords().catch(e => notify(e.message, true));

// 4. Lịch trình tuần & Xác nhận lịch hẹn
function getMonday(d) {
  const dt = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const day = dt.getDay();
  const diff = (day === 0 ? -6 : 1) - day;
  dt.setDate(dt.getDate() + diff);
  return dt;
}

function formatIsoDate(dt) {
  const y = dt.getFullYear();
  const m = String(dt.getMonth() + 1).padStart(2, '0');
  const d = String(dt.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function formatVnDate(dt) {
  const d = String(dt.getDate()).padStart(2, '0');
  const m = String(dt.getMonth() + 1).padStart(2, '0');
  const y = dt.getFullYear();
  return `${d}/${m}/${y}`;
}

const DAY_NAMES = ['Thứ 2', 'Thứ 3', 'Thứ 4', 'Thứ 5', 'Thứ 6', 'Thứ 7', 'Chủ nhật'];

async function loadSchedule() {
  try {
    const allAppts = await api('/api/appointments');
    const isDoctor = me && me.role === 'doctor';
    $('pendingApptCard').hidden = !isDoctor;

    if (isDoctor) {
      $('pendingApptRows').replaceChildren();
      const pendingList = allAppts.filter(a => {
        if (a.status !== 'pending') return false;
        if (a.doctor_username && a.doctor_username === me.username) return true;
        if (!a.doctor_username && (!me.department || a.department === me.department)) return true;
        return false;
      });

      for (const a of pendingList) {
        const tr = document.createElement('tr');
        cell(tr, '#' + a.id, 'text-center');
        cell(tr, a.patient_name);
        cell(tr, `${a.appointment_date} · ${a.appointment_time}`, 'text-center');
        cell(tr, `${a.department} (${a.branch})`);
        cell(tr, a.doctor_name || 'Chưa chỉ định (Cùng khoa)');
        cell(tr, a.reason);
        const actTd = cell(tr, '', 'text-center');
        const actBox = document.createElement('div');
        actBox.className = 'table-actions';

        const confirmBtn = document.createElement('button');
        confirmBtn.className = 'primary sm';
        confirmBtn.textContent = 'Xác nhận';
        confirmBtn.onclick = () => updateAppointmentStatus(a.id, 'confirmed');

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'danger-outline sm';
        cancelBtn.textContent = 'Báo huỷ';
        cancelBtn.onclick = () => updateAppointmentStatus(a.id, 'cancelled');

        actBox.append(confirmBtn, cancelBtn);
        actTd.append(actBox);
        $('pendingApptRows').append(tr);
      }

      if (!pendingList.length) {
        const tr = document.createElement('tr');
        const td = cell(tr, 'Hiện không có yêu cầu đặt lịch nào đang chờ xác nhận.', 'text-center');
        td.colSpan = 7;
        $('pendingApptRows').append(tr);
      }
    }

    const docFilter = $('scheduleDocFilter') ? $('scheduleDocFilter').value : 'ALL';
    const scheduledAppts = allAppts.filter(a => {
      if (a.status !== 'confirmed' && a.status !== 'cancelled') return false;
      if (docFilter !== 'ALL' && a.doctor_username !== docFilter) return false;
      return true;
    });

    const sunday = new Date(currentWeekMonday);
    sunday.setDate(sunday.getDate() + 6);
    $('scheduleSubheading').textContent = `Tuần từ ${formatVnDate(currentWeekMonday)} đến ${formatVnDate(sunday)}${me.role === 'nurse' ? ' • Chế độ chỉ xem dành cho Điều dưỡng / Y tá' : ''}`;

    const grid = $('weeklyGrid');
    grid.replaceChildren();
    const todayIso = formatIsoDate(new Date());

    for (let i = 0; i < 7; i++) {
      const colDate = new Date(currentWeekMonday);
      colDate.setDate(colDate.getDate() + i);
      const iso = formatIsoDate(colDate);

      const col = document.createElement('div');
      col.className = 'day-col';

      const head = document.createElement('div');
      head.className = 'day-header' + (iso === todayIso ? ' today' : '');
      const dName = document.createElement('span');
      dName.className = 'day-name';
      dName.textContent = DAY_NAMES[i];
      const dDate = document.createElement('span');
      dDate.className = 'day-date';
      dDate.textContent = formatVnDate(colDate);
      head.append(dName, dDate);

      const body = document.createElement('div');
      body.className = 'day-body';

      const dayItems = scheduledAppts
        .filter(a => a.appointment_date === iso)
        .sort((x, y) => (x.appointment_time || '').localeCompare(y.appointment_time || ''));

      for (const item of dayItems) {
        const card = document.createElement('div');
        card.className = 'appt-card' + (item.status === 'cancelled' ? ' cancelled' : '');

        const docLine = document.createElement('div');
        docLine.className = 'appt-card-doctor';
        docLine.textContent = item.doctor_name || 'BÁC SĨ ĐIỀU TRỊ';

        const patLine = document.createElement('div');
        patLine.className = 'appt-card-patient';
        patLine.textContent = 'Bệnh nhân: ';
        const patStrong = document.createElement('strong');
        patStrong.textContent = item.patient_name;
        patLine.append(patStrong);

        const timeLine = document.createElement('div');
        timeLine.className = 'appt-card-time';
        timeLine.textContent = `Thời gian: ${item.appointment_time}`;

        card.append(docLine, patLine, timeLine);

        if (item.status === 'cancelled') {
          const cancelTag = document.createElement('div');
          cancelTag.className = 'appt-card-cancelled-tag';
          cancelTag.textContent = 'Lịch đã huỷ';
          card.append(cancelTag);
        } else if (isDoctor && (!item.doctor_username || item.doctor_username === me.username)) {
          const actWrap = document.createElement('div');
          actWrap.className = 'appt-card-actions';
          const cancelBtn = document.createElement('button');
          cancelBtn.type = 'button';
          cancelBtn.className = 'appt-card-cancel-btn';
          cancelBtn.textContent = 'Báo huỷ lịch';
          cancelBtn.onclick = () => updateAppointmentStatus(item.id, 'cancelled');
          actWrap.append(cancelBtn);
          card.append(actWrap);
        }

        body.append(card);
      }

      if (!dayItems.length) {
        const empty = document.createElement('div');
        empty.className = 'day-empty';
        empty.textContent = 'Trống';
        body.append(empty);
      }

      col.append(head, body);
      grid.append(col);
    }

    tab('schedulePanel');
  } catch (e) {
    notify(e.message, true);
  }
}

async function updateAppointmentStatus(apptId, status) {
  try {
    await api(`/api/appointments/${apptId}/status`, 'PUT', { status });
    await loadSchedule();
    notify(status === 'confirmed' ? `Đã xác nhận lịch hẹn #${apptId} vào lịch trình.` : `Đã báo huỷ lịch hẹn #${apptId}.`);
  } catch (err) {
    notify(err.message, true);
  }
}

$('prevWeekBtn').onclick = () => {
  currentWeekMonday.setDate(currentWeekMonday.getDate() - 7);
  loadSchedule();
};
$('currentWeekBtn').onclick = () => {
  currentWeekMonday = getMonday(new Date());
  loadSchedule();
};
$('nextWeekBtn').onclick = () => {
  currentWeekMonday.setDate(currentWeekMonday.getDate() + 7);
  loadSchedule();
};
$('scheduleDocFilter').onchange = () => loadSchedule();
$('pendingRefreshBtn').onclick = () => loadSchedule();

// 5. Đăng nhập & Phân quyền hiển thị
async function signedIn() {
  me = await api('/api/me');
  document.body.classList.remove('logged-out');
  $('sidebar').hidden = false;
  $('topHeader').hidden = false;
  updateSidebarToggleLabel();
  const deptSuffix = me.department ? ` • Khoa ${me.department}` : '';
  $('asideRoleLabel').textContent = (roleLabels[me.role] || me.role) + deptSuffix;

  ALL_NAVS.forEach(id => { if ($(id)) $(id).hidden = true; });
  $('newRecordBtn').hidden = true;
  $('exportBtn').hidden = true;
  if ($('searchBoxWrap')) $('searchBoxWrap').hidden = false;

  await loadDoctorsDirectory();

  if (me.role === 'doctor') {
    $('patientsNav').hidden = false;
    $('patientsNav').textContent = 'Hồ sơ bệnh án';
    $('scheduleNav').hidden = false;
    $('scheduleNav').textContent = 'Lịch trình & Lịch hẹn';
    $('recordsHeading').textContent = 'Danh sách Hồ sơ Bệnh án';
    $('newRecordBtn').hidden = false;
    $('exportBtn').hidden = false;
  } else if (me.role === 'nurse') {
    $('patientsNav').hidden = false;
    $('patientsNav').textContent = 'Hồ sơ bệnh án';
    $('scheduleNav').hidden = false;
    $('scheduleNav').textContent = 'Lịch trình bác sĩ';
    $('recordsHeading').textContent = 'Danh sách Hồ sơ Bệnh án (Chế độ Xem)';
  } else if (me.role === 'patient') {
    $('patientsNav').hidden = false;
    $('patientsNav').textContent = 'Bệnh án cá nhân';
    $('recordsHeading').textContent = 'Hồ sơ Bệnh án Cá nhân';
    if ($('searchBoxWrap')) $('searchBoxWrap').hidden = true;
    $('profileNav').hidden = false;
    $('appointmentsNav').hidden = false;
  } else if (me.role === 'admin') {
    $('usersNav').hidden = false;
    $('revisionsNav').hidden = false;
    $('auditNav').hidden = false;
  }

  $('identity').replaceChildren();
  const label = document.createElement('span');
  label.textContent = `${me.full_name || me.username} (${roleLabels[me.role] || me.role}${deptSuffix})`;
  const logoutBtn = document.createElement('button');
  logoutBtn.textContent = 'Đăng xuất';
  logoutBtn.onclick = async () => {
    try {
      await api('/api/logout', 'POST', {});
      me = null;
      hideNotice();
      showLogin();
    } catch (e) {
      notify(e.message, true);
    }
  };
  $('identity').append(label, logoutBtn);

  const nowLocal = new Date();
  const earliest = new Date(nowLocal.getTime() + 30 * 60000);
  const todayIso = formatIsoDate(nowLocal);
  if ($('apptDate')) {
    $('apptDate').min = todayIso;
    if (!$('apptDate').value) {
      const eMin = earliest.getHours() * 60 + earliest.getMinutes();
      if (eMin > 15 * 60) {
        const tmr = new Date(nowLocal);
        tmr.setDate(tmr.getDate() + 1);
        $('apptDate').value = formatIsoDate(tmr);
        if ($('apptTime')) $('apptTime').value = '08:30';
      } else {
        $('apptDate').value = todayIso;
        if ($('apptTime')) {
          const adjMin = Math.max(7 * 60, eMin);
          const hh = String(Math.floor(adjMin / 60)).padStart(2, '0');
          const mm = String(adjMin % 60).padStart(2, '0');
          $('apptTime').value = `${hh}:${mm}`;
        }
      }
    }
  }
  if ($('apptPatientName')) $('apptPatientName').value = me.full_name || me.username;

  if (me.role === 'admin') {
    await loadUsers();
  } else {
    tab('workspace');
    await refreshRecords();
  }
}

$('loginForm').onsubmit = async e => {
  e.preventDefault();
  try {
    hideNotice();
    await api('/api/login', 'POST', {
      username: $('username').value.trim(),
      password: $('password').value
    });
    $('password').value = '';
    await signedIn();
  } catch (err) {
    notify(err.message, true);
  }
};

// 6. Đặt lịch khám trực tuyến
async function loadAppointments() {
  try {
    const rows = await api('/api/appointments');
    $('apptRows').replaceChildren();
    for (const r of rows) {
      const tr = document.createElement('tr');
      cell(tr, '#' + r.id, 'text-center');
      cell(tr, `${r.appointment_date} · ${r.appointment_time}`, 'text-center');
      const docDisplay = r.doctor_name ? `${r.department} — ${r.doctor_name}` : `${r.department} (Chờ phân công bác sĩ)`;
      cell(tr, `${docDisplay} [${r.branch}]`);
      cell(tr, r.reason);
      const stTd = cell(tr, '', 'text-center');
      const b = document.createElement('span');
      if (r.status === 'confirmed') {
        b.className = 'badge';
        b.textContent = 'Đã xác nhận';
      } else if (r.status === 'cancelled') {
        b.className = 'badge danger';
        b.textContent = 'Lịch đã huỷ';
      } else {
        b.className = 'badge warn';
        b.textContent = 'Đang chờ xác nhận';
      }
      stTd.append(b);
      $('apptRows').append(tr);
    }
    if (!rows.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, 'Chưa có lịch khám nào được đăng ký.', 'text-center');
      td.colSpan = 5;
      $('apptRows').append(tr);
    }
    tab('appointmentsPanel');
  } catch (e) {
    notify(e.message, true);
  }
}

$('appointmentForm').onsubmit = async e => {
  e.preventDefault();
  try {
    const chosenDate = $('apptDate').value;
    const chosenTime = $('apptTime').value;
    if (chosenDate && chosenTime) {
      const [y, m, d] = chosenDate.split('-').map(Number);
      const [hh, mm] = chosenTime.split(':').map(Number);
      const apptDt = new Date(y, m - 1, d, hh, mm, 0, 0);
      const earliestDt = new Date(Date.now() + 30 * 60000);
      earliestDt.setSeconds(0, 0);
      if (apptDt < earliestDt) {
        const eh = String(earliestDt.getHours()).padStart(2, '0');
        const em = String(earliestDt.getMinutes()).padStart(2, '0');
        throw new Error(`Giới hạn thời gian: Lịch khám phải cách thời điểm hiện tại tối thiểu 30 phút (Sớm nhất từ ${eh}:${em}).`);
      }
    }
    const res = await api('/api/appointments', 'POST', {
      patient_name: $('apptPatientName').value.trim(),
      branch: $('apptBranch').value,
      department: $('apptDept').value,
      doctor_username: $('apptDoctor').value || '',
      appointment_date: $('apptDate').value,
      appointment_time: $('apptTime').value,
      reason: $('apptReason').value.trim()
    });
    $('apptReason').value = '';
    await loadAppointments();
    notify(`Đã gửi phiếu đăng ký lịch khám lúc ${res.appointment_time} ngày ${res.appointment_date} (Trạng thái: Đang chờ xác nhận).`);
  } catch (err) {
    notify(err.message, true);
  }
};

// 7. Thông tin cá nhân & Quản trị hệ thống
async function loadProfile() {
  try {
    const p = await api('/api/profile');
    $('profUsername').value = p.username;
    $('profLinkedId').value = p.linked_patient_id || '—';
    $('profFullName').value = p.full_name || '';
    $('profBirthYear').value = p.birth_year || 1990;
    $('profPhone').value = p.phone || '';
    $('profAddress').value = p.address || '';
    tab('profilePanel');
  } catch (e) {
    notify(e.message, true);
  }
}

$('profileForm').onsubmit = async e => {
  e.preventDefault();
  try {
    await api('/api/profile', 'PUT', {
      full_name: $('profFullName').value.trim(),
      birth_year: Number($('profBirthYear').value),
      phone: $('profPhone').value.trim(),
      address: $('profAddress').value.trim()
    });
    notify('Đã lưu thông tin cá nhân.');
  } catch (err) {
    notify(err.message, true);
  }
};

async function loadRevisions() {
  try {
    const filterId = ($('revFilterInput').value || '').trim().toUpperCase();
    const url = filterId ? `/api/revisions?record_id=${encodeURIComponent(filterId)}` : '/api/revisions';
    const rows = await api(url);
    $('revisionRows').replaceChildren();
    for (const r of rows) {
      const tr = document.createElement('tr');
      cell(tr, (r.edited_at || '').replace('T', ' ').replace('Z', ''), 'text-center');
      cell(tr, r.record_id, 'text-center');
      cell(tr, `${r.username} (ID: ${r.user_id})`);
      cell(tr, r.source_ip, 'text-center');
      const actTd = cell(tr, '', 'text-center');
      const b = document.createElement('span');
      b.className = 'badge ' + (r.action === 'DELETE' ? 'danger' : (r.action === 'CREATE' ? 'warn' : ''));
      b.textContent = r.action;
      actTd.append(b);
      cell(tr, (r.changed_fields || []).join(', '));
      const diffTd = cell(tr, '');
      const pre = document.createElement('div');
      pre.className = 'diff-box';
      const lines = [];
      for (const k of (r.changed_fields || [])) {
        const ov = r.old_values && r.old_values[k] !== undefined ? r.old_values[k] : '∅';
        const nv = r.new_values && r.new_values[k] !== undefined ? r.new_values[k] : '∅';
        lines.push(`${k}: "${ov}" ➔ "${nv}"`);
      }
      pre.textContent = lines.length ? lines.join('  •  ') : r.diff_summary;
      diffTd.append(pre);
      $('revisionRows').append(tr);
    }
    if (!rows.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, 'Chưa có lịch sử chỉnh sửa.', 'text-center');
      td.colSpan = 7;
      $('revisionRows').append(tr);
    }
    tab('revisionsPanel');
  } catch (e) {
    notify(e.message, true);
  }
}

function renderUsersTable() {
  const q = ($('userSearchInput') ? $('userSearchInput').value : '').trim().toLocaleLowerCase('vi');
  $('userRows').replaceChildren();
  const filtered = usersList.filter(u =>
    [u.id, u.username, roleLabels[u.role] || u.role, u.full_name, u.department, u.linked_patient_id]
      .join(' ')
      .toLocaleLowerCase('vi')
      .includes(q)
  );
  for (const u of filtered) {
    const tr = document.createElement('tr');
    cell(tr, '#' + u.id, 'text-center');
    cell(tr, u.username);
    const rTd = cell(tr, '', 'text-center');
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = roleLabels[u.role] || u.role;
    rTd.append(badge);
    cell(tr, u.full_name);
    cell(tr, u.department || '—');
    cell(tr, u.linked_patient_id || '—', 'text-center');
    const actTd = cell(tr, '', 'text-center');
    if (u.username !== me.username) {
      const delBtn = document.createElement('button');
      delBtn.className = 'danger-outline sm';
      delBtn.textContent = 'Xóa';
      delBtn.onclick = async () => {
        try {
          await api('/api/users/' + u.username, 'DELETE', {});
          await loadUsers();
          notify(`Đã xóa tài khoản ${u.username}.`);
        } catch (err) {
          notify(err.message, true);
        }
      };
      actTd.append(delBtn);
    } else {
      actTd.textContent = 'Đang sử dụng';
    }
    $('userRows').append(tr);
  }
  if (!filtered.length) {
    const tr = document.createElement('tr');
    const td = cell(tr, 'Không tìm thấy tài khoản phù hợp.', 'text-center');
    td.colSpan = 7;
    $('userRows').append(tr);
  }
}

async function loadUsers() {
  try {
    const [users, status] = await Promise.all([
      api('/api/users'),
      api('/api/system/status')
    ]);
    usersList = users || [];
    $('sysUserCount').textContent = String(usersList.length);
    $('sysAlertCount').textContent = `${status.metrics.total_audit_events} sự kiện`;
    $('adminIpDisplay').textContent = me ? me.source_ip : '—';
    renderUsersTable();
    tab('usersPanel');
  } catch (e) {
    notify(e.message, true);
  }
}

$('userForm').onsubmit = async e => {
  e.preventDefault();
  const uname = $('uUsername').value.trim();
  const roleVal = $('uRole').value;
  const payload = {
    username: uname,
    role: roleVal,
    full_name: $('uFullName').value.trim(),
    department: (roleVal === 'doctor' || roleVal === 'nurse') ? ($('uDepartment').value || null) : null,
    linked_patient_id: $('uLinkedId').value.trim() || null,
    password: $('uPassword').value
  };
  try {
    await api('/api/users', 'POST', payload);
    $('uPassword').value = '';
    await loadUsers();
    notify(`Đã tạo tài khoản ${uname}.`);
  } catch (err) {
    try {
      await api('/api/users/' + uname, 'PUT', payload);
      $('uPassword').value = '';
      await loadUsers();
      notify(`Đã cập nhật tài khoản ${uname}.`);
    } catch (err2) {
      notify(err2.message || err.message, true);
    }
  }
};

function renderAuditTable() {
  const q = ($('auditSearchInput') ? $('auditSearchInput').value : '').trim().toLocaleLowerCase('vi');
  $('auditRows').replaceChildren();
  const filtered = auditList.filter(entry =>
    [entry.timestamp, entry.username, entry.role, entry.source_ip, entry.event, entry.target, entry.detail, entry.status]
      .join(' ')
      .toLocaleLowerCase('vi')
      .includes(q)
  );
  for (const entry of filtered) {
    const row = document.createElement('tr');
    cell(row, (entry.timestamp || '').replace('T', ' ').replace('Z', ''), 'text-center');
    cell(row, `${entry.username} (${entry.user_id ?? '—'})`);
    cell(row, entry.role, 'text-center');
    cell(row, entry.source_ip, 'text-center');
    cell(row, entry.event);
    cell(row, entry.target);
    cell(row, entry.detail || '');
    cell(row, String(entry.status), 'text-center');
    $('auditRows').append(row);
  }
  if (!filtered.length) {
    const row = document.createElement('tr');
    const td = cell(row, 'Không có bản ghi nhật ký phù hợp.', 'text-center');
    td.colSpan = 8;
    $('auditRows').append(row);
  }
}

async function loadAudit() {
  try {
    auditList = await api('/api/audit');
    renderAuditTable();
    tab('auditPanel');
  } catch (e) {
    notify(e.message, true);
  }
}

$('exportBtn').onclick = async () => {
  try {
    const response = await fetch('/api/export');
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error);
    }
    const url = URL.createObjectURL(await response.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = 'medicare-records.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    notify('Đã kết xuất danh sách hồ sơ CSV.');
  } catch (e) {
    notify(e.message, true);
  }
};

if ($('userSearchInput')) {
  $('userSearchInput').oninput = renderUsersTable;
  $('userSearchInput').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); renderUsersTable(); } };
}
if ($('userSearchBtn')) $('userSearchBtn').onclick = renderUsersTable;

if ($('revFilterInput')) {
  $('revFilterInput').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); loadRevisions(); } };
}
if ($('revSearchBtn')) $('revSearchBtn').onclick = loadRevisions;

if ($('auditSearchInput')) {
  $('auditSearchInput').oninput = renderAuditTable;
  $('auditSearchInput').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); renderAuditTable(); } };
}
if ($('auditSearchBtn')) $('auditSearchBtn').onclick = renderAuditTable;

$('patientsNav').onclick = () => { if (me && me.role !== 'admin') { hideNotice(); tab('workspace'); refreshRecords(); } };
$('scheduleNav').onclick = () => { if (me && (me.role === 'doctor' || me.role === 'nurse')) { hideNotice(); loadSchedule(); } };
$('profileNav').onclick = () => { hideNotice(); loadProfile(); };
$('appointmentsNav').onclick = () => { hideNotice(); loadAppointments(); };
$('apptRefreshBtn').onclick = loadAppointments;
$('usersNav').onclick = () => { hideNotice(); loadUsers(); };
$('usersRefreshBtn').onclick = loadUsers;
$('revisionsNav').onclick = () => { hideNotice(); loadRevisions(); };
$('revRefreshBtn').onclick = loadRevisions;
$('auditNav').onclick = () => { hideNotice(); loadAudit(); };
$('auditRefresh').onclick = loadAudit;

signedIn().catch(() => showLogin());
