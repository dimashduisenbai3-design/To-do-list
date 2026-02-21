const API = 'http://127.0.0.1:8000/tasks';

let allTasks = [];
let currentFilter = 'all';

// ===== ИНИЦИАЛИЗАЦИЯ =====
document.addEventListener('DOMContentLoaded', () => {
  fetchTasks();

  document.getElementById('add-form').addEventListener('submit', handleAdd);

  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderTasks();
    });
  });
});

// ===== ЗАГРУЗКА ЗАДАЧ =====
async function fetchTasks() {
  showLoading(true);
  try {
    const res = await fetch(API);
    if (!res.ok) throw new Error('Нет ответа от сервера');
    allTasks = await res.json();
    renderTasks();
  } catch (err) {
    showToast('❌ Сервер недоступен. Запущен ли FastAPI?', 'error');
    showLoading(false);
  }
}

// ===== РЕНДЕР =====
function renderTasks() {
  const list = document.getElementById('task-list');
  const empty = document.getElementById('empty-state');

  const filtered = currentFilter === 'all'
    ? allTasks
    : allTasks.filter(t => String(t.status) === currentFilter);

  document.getElementById('task-count').textContent = allTasks.length;

  list.innerHTML = '';
  showLoading(false);

  if (filtered.length === 0) {
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');

  filtered.forEach((task, i) => {
    const card = createTaskCard(task, i);
    list.appendChild(card);
  });
}

function createTaskCard(task, index) {
  const isDone = task.status == 1;
  const card = document.createElement('div');
  card.className = `task-card${isDone ? ' done' : ''}`;
  card.dataset.id = task.id;
  card.style.animationDelay = `${index * 40}ms`;

  card.innerHTML = `
    <button class="status-toggle" title="Изменить статус">
      ${isDone ? '✓' : ''}
    </button>
    <div class="task-info">
      <div class="task-title">${escapeHtml(task.title)}</div>
      <div class="task-meta">
        <span class="meta-chip">👤 Пользователь ${task.user_id}</span>
        ${task.category_id ? `<span class="meta-chip">🏷️ Кат. ${task.category_id}</span>` : ''}
        <span class="meta-chip">#${task.id}</span>
      </div>
    </div>
    <span class="status-badge ${isDone ? 'done' : 'pending'}">
      ${isDone ? 'Выполнено' : 'В работе'}
    </span>
    <button class="btn-delete" title="Удалить">✕</button>
  `;

  card.querySelector('.btn-delete').addEventListener('click', () => handleDelete(task.id, card));
  card.querySelector('.status-toggle').addEventListener('click', () => handleToggle(task, card));

  return card;
}

// ===== ДОБАВИТЬ ЗАДАЧУ =====
async function handleAdd(e) {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector('.btn-add');

  const title = form.title.value.trim();
  const user_id = parseInt(form.user_id.value);
  const category_id = form.category_id.value ? parseInt(form.category_id.value) : null;

  if (!title || !user_id) return;

  btn.textContent = 'Отправка...';
  btn.disabled = true;

  try {
    const body = { title, status: 0, user_id };
    if (category_id) body.category_id = category_id;

    const res = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) throw new Error(`Ошибка: ${res.status}`);
    const newTask = await res.json();

    allTasks.unshift(newTask);
    form.reset();
    renderTasks();
    showToast('✦ Задача добавлена!', 'success');
  } catch (err) {
    showToast('Ошибка добавления: ' + err.message, 'error');
  } finally {
    btn.innerHTML = '<span>+</span> Добавить';
    btn.disabled = false;
  }
}

// ===== УДАЛИТЬ ЗАДАЧУ =====
async function handleDelete(id, cardEl) {
  cardEl.style.transition = 'opacity 0.25s, transform 0.25s';
  cardEl.style.opacity = '0';
  cardEl.style.transform = 'translateX(24px)';

  try {
    const res = await fetch(`${API}/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Ошибка: ${res.status}`);

    allTasks = allTasks.filter(t => t.id !== id);
    setTimeout(() => renderTasks(), 260);
    showToast('Задача удалена', 'success');
  } catch (err) {
    cardEl.style.opacity = '1';
    cardEl.style.transform = '';
    showToast('Ошибка удаления: ' + err.message, 'error');
  }
}

// ===== ИЗМЕНИТЬ СТАТУС =====
async function handleToggle(task, cardEl) {
  const newStatus = task.status == 1 ? 0 : 1;

  task.status = newStatus;
  const isDone = newStatus == 1;
  cardEl.classList.toggle('done', isDone);
  cardEl.querySelector('.status-toggle').textContent = isDone ? '✓' : '';
  cardEl.querySelector('.status-badge').className = `status-badge ${isDone ? 'done' : 'pending'}`;
  cardEl.querySelector('.status-badge').textContent = isDone ? 'Выполнено' : 'В работе';

  try {
    await fetch(`${API}/${task.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
  } catch {
    // PATCH не поддерживается — статус обновляется только в UI
  }

  if (currentFilter !== 'all') renderTasks();
}

// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
function showLoading(show) {
  const list = document.getElementById('task-list');
  const loading = list.querySelector('.loading-state');

  if (show && !loading) {
    list.innerHTML = `
      <div class="loading-state">
        <div class="spinner"></div>
        <p>Загрузка...</p>
      </div>`;
  } else if (!show && loading) {
    loading.remove();
  }
}

let toastTimer;
function showToast(msg, type = 'success') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = `toast ${type} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2800);
}

function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
