<script>
  import { onMount } from 'svelte';

  const storageKey = 'simple-vault-session';
  const statuses = { pending: 'Ожидает решения', approved: 'Доступ открыт', denied: 'Отклонён', revoked: 'Доступ закрыт' };
  let session = $state(null);
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');
  let authMode = $state('login');
  let email = $state('');
  let password = $state('');
  let list = $state('owned');
  let owned = $state([]);
  let shared = $state([]);
  let selected = $state(null);
  let history = $state(null);
  let secretInput = $state('');
  let title = $state('');
  let text = $state('');
  let ttl = $state(86400);
  let revokeUserID = $state('');
  let lastResponse = $state(null);
  let showResponse = $state(false);
  let confirmDelete = $state(false);
  const items = $derived(list === 'owned' ? owned : shared);
  const isOwner = $derived(selected && owned.some((item) => item.id === selected.id));

  function saveSession(value) {
    session = value;
    try {
      if (value) sessionStorage.setItem(storageKey, JSON.stringify(value));
      else sessionStorage.removeItem(storageKey);
    } catch { /* The session can still work in memory if storage is unavailable. */ }
  }

  function signOut() {
    saveSession(null);
    owned = [];
    shared = [];
    selected = null;
    history = null;
    lastResponse = null;
    password = '';
    text = '';
    title = '';
    revokeUserID = '';
    confirmDelete = false;
    error = '';
    notice = '';
  }

  $effect(() => {
    if (!session) return;
    const timer = setTimeout(() => {
      signOut();
      notice = 'Сессия истекла. Войдите снова.';
    }, Math.max(0, session.expiresAt - Date.now()));
    return () => clearTimeout(timer);
  });

  async function run(action) {
    if (busy) return;
    busy = true;
    error = '';
    notice = '';
    try { await action(); }
    catch (failure) { error = failure.message || 'Не удалось выполнить запрос.'; }
    finally { busy = false; }
  }

  async function request(method, path, body, trace = true) {
    const token = path.startsWith('/secrets') ? session?.token : null;
    const headers = { Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const start = performance.now();
    let response;
    try {
      response = await fetch(path, {
        method, headers, credentials: 'omit', cache: 'no-store',
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(20000),
      });
    } catch (failure) {
      if (trace) lastResponse = { method, path, status: 'Ошибка сети', ms: Math.round(performance.now() - start), body: null };
      throw new Error(failure.name === 'TimeoutError' ? 'Сервер не ответил за 20 секунд.' : 'Нет соединения с API. Проверьте, запущен ли стек.');
    }
    const raw = await response.text();
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; }
    catch { data = raw; }
    if (trace) {
      lastResponse = {
        method, path, status: response.status, ms: Math.round(performance.now() - start),
        body: data?.access_token ? { ...data, access_token: '[JWT получен, значение скрыто]' } : data,
      };
    }
    if (token && response.status === 401) {
      const result = lastResponse;
      signOut();
      lastResponse = result;
      throw new Error('Сессия истекла или недействительна. Войдите снова.');
    }
    if (token && session?.token !== token) throw new Error('Сессия завершена. Войдите снова.');
    if (!response.ok) {
      const retry = response.headers.get('Retry-After');
      throw new Error(`${response.status}: ${data?.message || 'Ошибка API'}${retry ? ` Повторите через ${retry} с.` : ''}`);
    }
    return { data, status: response.status };
  }

  async function loadList(kind = list, trace = true) {
    const { data } = await request('GET', kind === 'owned' ? '/secrets' : '/secrets/shared', undefined, trace);
    if (kind === 'owned') owned = data || [];
    else shared = data || [];
  }

  async function authenticate() {
    const credentials = { email: email.trim(), password };
    if (authMode === 'register') {
      const { data } = await request('POST', '/auth/register', credentials);
      authMode = 'login';
      notice = `Аккаунт создан. Теперь войдите. ID: ${data.user_id}`;
      return;
    }
    const { data } = await request('POST', '/auth/login', credentials);
    let userID = '';
    try { userID = JSON.parse(atob(data.access_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).user_id; }
    catch { /* This is only a display hint; the gateway verifies the JWT. */ }
    saveSession({ token: data.access_token, email: credentials.email, userID, expiresAt: Date.now() + data.expires_in * 1000 });
    password = '';
    list = 'owned';
    await loadList('owned', false);
    if (secretInput) await openSecret(secretInput);
  }

  function parseID(value) {
    let id = value.trim();
    if (!/^[0-9a-f-]+$/i.test(id)) {
      try {
        const url = new URL(id, window.location.origin);
        id = url.pathname.match(/^\/secrets\/([^/]+)\/?$/)?.[1] || '';
      } catch { id = ''; }
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new Error('Введите UUID секрета или ссылку вида /secrets/UUID.');
    }
    return id.toLowerCase();
  }

  async function openSecret(value) {
    const id = parseID(value);
    selected = null;
    history = null;
    confirmDelete = false;
    revokeUserID = '';
    const { data, status } = await request('GET', `/secrets/${id}`);
    selected = { ...data, id, pending: status === 202 };
    secretInput = id;
    window.history.replaceState(null, '', `/secrets/${id}`);
  }

  function newSecret() {
    selected = null;
    history = null;
    confirmDelete = false;
    error = '';
    notice = '';
    window.history.replaceState(null, '', '/');
  }

  async function createSecret() {
    if (new TextEncoder().encode(text).length > 10240) throw new Error('Текст секрета должен быть не больше 10 240 байт UTF-8.');
    const { data } = await request('POST', '/secrets', { title, text, ttl_seconds: Number(ttl) });
    selected = { ...data, title, pending: false };
    secretInput = data.id;
    title = '';
    text = '';
    history = null;
    list = 'owned';
    window.history.replaceState(null, '', `/secrets/${data.id}`);
    notice = 'Секрет создан.';
    await loadList('owned', false);
  }

  async function loadHistory(trace = true) {
    const { data } = await request('GET', `/secrets/${selected.id}/requests`, undefined, trace);
    history = { requests: data.requests || [], views: data.views || [] };
  }

  async function decide(id, decision) {
    await request('POST', `/secrets/${selected.id}/requests/${id}`, { decision });
    await loadHistory(false);
    await loadList('owned', false);
  }

  async function revokeAccess() {
    const userID = parseID(revokeUserID);
    await request('DELETE', `/secrets/${selected.id}/access/${userID}`);
    revokeUserID = '';
    notice = 'Доступ пользователя закрыт.';
    await loadHistory(false);
  }

  async function deleteSecret() {
    await request('DELETE', `/secrets/${selected.id}`);
    newSecret();
    secretInput = '';
    notice = 'Секрет удалён.';
    await loadList('owned', false);
  }

  async function copy(value) {
    try {
      await navigator.clipboard.writeText(value);
      notice = 'Скопировано.';
    } catch { error = 'Не удалось скопировать. Выделите и скопируйте текст вручную.'; }
  }

  function date(value) {
    return new Date(value).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  }

  onMount(() => {
    secretInput = window.location.pathname.match(/^\/secrets\/([^/]+)\/?$/)?.[1] || '';
    try {
      const stored = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
      if (stored?.token && stored.expiresAt > Date.now()) session = stored;
      else sessionStorage.removeItem(storageKey);
    } catch { /* Ignore an expired or invalid saved session. */ }
    if (session) run(async () => {
      await loadList('owned', false);
      if (secretInput) await openSecret(secretInput);
    });
  });
</script>

<div class="shell">
  <header class="topbar">
    <a class="brand" href="/">simple-vault</a>
    {#if session}
      <div class="account">
        <details>
          <summary>{session.email}</summary>
          <div class="account-info">
            <span>ID пользователя</span>
            <code>{session.userID || '—'}</code>
            <span>Сессия до {date(session.expiresAt)}</span>
          </div>
        </details>
        <button class="quiet" disabled={busy} onclick={signOut}>Выйти</button>
      </div>
    {/if}
  </header>

  <main>
    <div class="messages" aria-live="polite" aria-atomic="true">
      {#if error}<p class="message error" role="alert">{error}</p>{/if}
      {#if notice}<p class="message">{notice}</p>{/if}
    </div>

    {#if !session}
      <section class="login" aria-label="Авторизация">
        <h1>{authMode === 'login' ? 'Вход' : 'Регистрация'}</h1>
        {#if secretInput}<p class="muted">Войдите, чтобы открыть секрет по ссылке.</p>{/if}
        <form onsubmit={(event) => { event.preventDefault(); run(authenticate); }}>
          <fieldset disabled={busy}>
            <label>Email<input type="email" autocomplete="username" bind:value={email} required /></label>
            <label>Пароль<input type="password" autocomplete={authMode === 'login' ? 'current-password' : 'new-password'} bind:value={password} minlength={authMode === 'register' ? 10 : undefined} required /></label>
            {#if authMode === 'register'}<p class="hint">Не меньше 10 символов.</p>{/if}
            <div class="actions">
              <button class="primary" type="submit">{busy ? 'Подождите…' : authMode === 'login' ? 'Войти' : 'Создать аккаунт'}</button>
              <button type="button" class="quiet" onclick={() => { authMode = authMode === 'login' ? 'register' : 'login'; error = ''; notice = ''; }}>{authMode === 'login' ? 'Регистрация' : 'Уже есть аккаунт'}</button>
            </div>
          </fieldset>
        </form>
        <p class="hint login-hint">Для проверки доступа от другого пользователя откройте отдельное приватное окно браузера.</p>
      </section>
    {:else}
      <div class="page-heading">
        <h1>Секреты</h1>
        <button class="primary" disabled={busy} onclick={newSecret}>Новый секрет</button>
      </div>

      <form class="open-form" onsubmit={(event) => { event.preventDefault(); run(() => openSecret(secretInput)); }}>
        <label for="secret-link">Открыть по ссылке или ID</label>
        <div class="input-row">
          <input id="secret-link" bind:value={secretInput} placeholder="UUID или http://localhost/secrets/…" required disabled={busy} spellcheck="false" />
          <button disabled={busy} type="submit">Открыть</button>
        </div>
      </form>

      <div class="workspace" aria-busy={busy}>
        <aside class="sidebar" aria-label="Список секретов">
          <nav class="tabs" aria-label="Какие секреты показать">
            <button class:active={list === 'owned'} aria-pressed={list === 'owned'} disabled={busy} onclick={() => run(async () => { list = 'owned'; await loadList(); })}>Мои</button>
            <button class:active={list === 'shared'} aria-pressed={list === 'shared'} disabled={busy} onclick={() => run(async () => { list = 'shared'; await loadList(); })}>Доступные мне</button>
          </nav>
          <div class="list-heading">
            <span class="muted">{items.length} секретов</span>
            <button class="quiet" disabled={busy} onclick={() => run(() => loadList())}>Обновить</button>
          </div>
          {#if !items.length}
            <p class="empty">{busy ? 'Загрузка…' : list === 'owned' ? 'Вы ещё не создали ни одного секрета.' : 'Здесь появятся секреты, к которым вам открыли доступ.'}</p>
          {/if}
          <ul class="secret-list">
            {#each items as item (item.id)}
              <li>
                <button class:selected={selected?.id === item.id} disabled={busy} onclick={() => run(() => openSecret(item.id))}>
                  <strong>{item.title}</strong>
                  {#if item.owner_email}<span>{item.owner_email}</span>{/if}
                  <span>До {date(item.expires_at)}</span>
                  {#if item.pending_requests}<span class="pending">Запросов: {item.pending_requests}</span>{/if}
                </button>
              </li>
            {/each}
          </ul>
        </aside>

        <section class="editor" aria-label="Содержимое секрета">
          {#if !selected}
            <h2>Новый секрет</h2>
            <form onsubmit={(event) => { event.preventDefault(); run(createSecret); }}>
              <fieldset disabled={busy}>
                <label>Название<input bind:value={title} required /></label>
                <p class="hint">Название видно в списке и письмах. Сам секрет пишите ниже.</p>
                <label>Текст<textarea bind:value={text} rows="7" required spellcheck="false"></textarea></label>
                <label>Срок действия
                  <select bind:value={ttl}>
                    <option value={300}>5 минут</option>
                    <option value={3600}>1 час</option>
                    <option value={86400}>1 день</option>
                    <option value={604800}>7 дней</option>
                  </select>
                </label>
                <button class="primary" type="submit">{busy ? 'Подождите…' : 'Создать секрет'}</button>
              </fieldset>
            </form>
          {:else}
            <h2>{selected.title || 'Доступ к секрету'}</h2>
            <p class="secret-id"><code>{selected.id}</code></p>
            {#if selected.expires_at}<p class="muted">Действует до {date(selected.expires_at)}</p>{/if}
            {#if selected.pending}
              <p class="message">Запрос отправлен автору. Дождитесь одобрения и проверьте доступ ещё раз.</p>
              <button disabled={busy} onclick={() => run(() => openSecret(selected.id))}>Проверить доступ</button>
            {:else}
              {#if selected.text !== undefined}
                <pre class="secret-text">{selected.text}</pre>
              {/if}
              <div class="actions">
                <button disabled={busy} onclick={() => run(() => openSecret(selected.id))}>{selected.text === undefined ? 'Открыть текст' : 'Открыть ещё раз'}</button>
                {#if selected.text !== undefined}<button disabled={busy} onclick={() => copy(selected.text)}>Скопировать текст</button>{/if}
                <button disabled={busy} onclick={() => copy(`${window.location.origin}/secrets/${selected.id}`)}>Скопировать ссылку</button>
              </div>
              {#if selected.text !== undefined}<p class="hint">Каждое открытие записывается в историю просмотров.</p>{/if}
              {#if isOwner}
                <div class="section-heading">
                  <h3>Доступ и просмотры</h3>
                  <button disabled={busy} onclick={() => run(() => loadHistory())}>{history ? 'Обновить' : 'Загрузить'}</button>
                </div>
                {#if history}
                  {#if !history.requests.length}<p class="muted">Запросов доступа пока нет.</p>{/if}
                  <ul class="request-list">
                    {#each history.requests as item (item.id)}
                      <li>
                        <div><strong>{item.requester_email}</strong><span class="muted">{statuses[item.status]} · {date(item.created_at)}</span></div>
                        {#if item.status === 'pending'}
                          <div class="actions">
                            <button disabled={busy} onclick={() => run(() => decide(item.id, 'approve'))}>Одобрить</button>
                            <button disabled={busy} onclick={() => run(() => decide(item.id, 'deny'))}>Отклонить</button>
                          </div>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                  <details class="revoke-access">
                    <summary>Закрыть доступ пользователю</summary>
                    <form onsubmit={(event) => { event.preventDefault(); run(revokeAccess); }}>
                      <label for="user-id">ID пользователя</label>
                      <div class="input-row">
                        <input id="user-id" bind:value={revokeUserID} placeholder="UUID пользователя" required disabled={busy} />
                        <button disabled={busy} type="submit">Закрыть доступ</button>
                      </div>
                      <p class="hint">Пользователь может посмотреть свой ID в меню аккаунта вверху.</p>
                    </form>
                  </details>
                  <h3>История просмотров</h3>
                  {#if !history.views.length}<p class="muted">Секрет ещё никто не открывал.</p>{:else}
                    <div class="table-scroll">
                      <table>
                        <thead><tr><th>Email</th><th>IP</th><th>Время</th></tr></thead>
                        <tbody>{#each history.views as view}<tr><td>{view.email}</td><td><code>{view.ip}</code></td><td>{date(view.viewed_at)}</td></tr>{/each}</tbody>
                      </table>
                    </div>
                  {/if}
                {/if}
                <div class="delete-area">
                  {#if confirmDelete}
                    <p>Удалить секрет вместе с запросами и историей просмотров?</p>
                    <div class="actions">
                      <button class="danger" disabled={busy} onclick={() => run(deleteSecret)}>Да, удалить</button>
                      <button disabled={busy} onclick={() => confirmDelete = false}>Отмена</button>
                    </div>
                  {:else}
                    <button class="quiet danger" disabled={busy} onclick={() => confirmDelete = true}>Удалить секрет</button>
                  {/if}
                </div>
              {/if}
            {/if}
          {/if}
        </section>
      </div>
    {/if}

    {#if lastResponse}
      <details class="response" bind:open={showResponse}>
        <summary>Ответ API <code>{lastResponse.method} {lastResponse.path}</code> <strong>{lastResponse.status}</strong> <span class="muted">{lastResponse.ms} мс</span></summary>
        <pre>{lastResponse.body === null ? '(пустой ответ)' : JSON.stringify(lastResponse.body, null, 2)}</pre>
      </details>
    {/if}
  </main>
</div>
