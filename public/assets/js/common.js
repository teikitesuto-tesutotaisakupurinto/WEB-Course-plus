
/**
 * WEB Course-plus 共通UI
 * - 生徒用サイドバー
 * - サイドバー開閉
 * - 現在ページの自動判定
 * - 共通トースト
 * - 日付・時刻表示
 *
 * このファイルはFirebase認証処理を行いません。
 * 認証・権限確認は各ページの認証処理で行ってください。
 */

(() => {
  "use strict";

  const APP = {
    name: "WEB Course-plus",
    studentMenu: [
      {
        section: "学習メニュー",
        items: [
          {
            label: "ホーム",
            href: "/student/index.html",
            icon: "home"
          },
          {
            label: "授業予定",
            href: "/student/schedule.html",
            icon: "calendar"
          },
          {
            label: "授業ルーム",
            href: "/lesson/room.html",
            icon: "video"
          },
          {
            label: "教材",
            href: "/student/materials.html",
            icon: "book"
          },
          {
            label: "学習記録",
            href: "/student/records.html",
            icon: "chart"
          }
        ]
      },
      {
        section: "その他",
        items: [
          {
            label: "お知らせ",
            href: "/student/announcements.html",
            icon: "bell"
          },
          {
            label: "設定",
            href: "/student/settings.html",
            icon: "settings"
          }
        ]
      }
    ]
  };

  const ICONS = {
    home: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="m3 10 9-7 9 7"></path>
        <path d="M5 9v12h14V9"></path>
        <path d="M9 21v-7h6v7"></path>
      </svg>
    `,
    calendar: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <rect x="3" y="5" width="18" height="16" rx="2"></rect>
        <path d="M16 3v4M8 3v4M3 10h18"></path>
        <path d="M8 14h3M8 17h6"></path>
      </svg>
    `,
    video: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <rect x="3" y="6" width="13" height="12" rx="2"></rect>
        <path d="m16 10 5-3v10l-5-3z"></path>
      </svg>
    `,
    book: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v17H6.5A2.5 2.5 0 0 0 4 21.5z"></path>
        <path d="M4 4.5v17M8 6h8M8 10h7"></path>
      </svg>
    `,
    chart: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M3 3v18h18"></path>
        <path d="m7 14 4-4 3 3 6-7"></path>
      </svg>
    `,
    bell: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"></path>
        <path d="M10 21h4"></path>
      </svg>
    `,
    settings: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="3"></circle>
        <path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.6.9l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.6-.9l-1.7.6-1.4-2.4 1.4-1.1a7 7 0 0 1 0-1.9l-1.4-1.1 1.4-2.4 1.7.6a8 8 0 0 1 1.6-.9l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.6.9l1.7-.6 1.4 2.4-1.4 1.1a7 7 0 0 1-.1 1.8z"></path>
      </svg>
    `,
    logout: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M10 17l5-5-5-5"></path>
        <path d="M15 12H3"></path>
        <path d="M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7"></path>
      </svg>
    `,
    menu: `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 6h16M4 12h16M4 18h16"></path>
      </svg>
    `
  };

  const SELECTORS = {
    sidebar: "[data-app-sidebar], #appSidebar",
    main: "[data-app-main], #appMain",
    toggle: "[data-sidebar-toggle], #sidebarToggle"
  };

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[character]);
  }

  function getCurrentPath() {
    const current = new URL(location.href);
    return current.pathname.replace(/\/+$/, "") || "/";
  }

  function isCurrentPage(href) {
    try {
      const target = new URL(href, location.origin);
      const targetPath = target.pathname.replace(/\/+$/, "") || "/";
      const currentPath = getCurrentPath();

      if (targetPath === currentPath) return true;

      // 授業ルームは lessonId 付きURLでも同じメニューを選択する
      if (
        targetPath === "/lesson/room.html" &&
        currentPath.startsWith("/lesson/")
      ) {
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  function getIcon(name) {
    return ICONS[name] || "";
  }

  function getUserInitial(name) {
    const value = String(name || "生徒").trim();
    return value ? value.slice(0, 1).toUpperCase() : "生";
  }

  function createMenuHTML(menu) {
    return menu.map(section => {
      const items = section.items.map(item => {
        const active = isCurrentPage(item.href);
        const badge = item.badge
          ? `<span class="app-nav-badge">${escapeHTML(item.badge)}</span>`
          : "";

        return `
          <li class="app-nav-item">
            <a
              class="app-nav-link${active ? " active" : ""}"
              href="${escapeHTML(item.href)}"
              ${active ? 'aria-current="page"' : ""}
              title="${escapeHTML(item.label)}"
            >
              <span class="app-nav-icon">${getIcon(item.icon)}</span>
              <span class="app-nav-label">${escapeHTML(item.label)}</span>
              ${badge}
            </a>
          </li>
        `;
      }).join("");

      return `
        <div class="app-nav-group">
          <div class="app-nav-section">${escapeHTML(section.section)}</div>
          <ul class="app-nav-list">${items}</ul>
        </div>
      `;
    }).join("");
  }

  function getSidebarElement() {
    return document.querySelector(SELECTORS.sidebar);
  }

  function getMainElement() {
    return document.querySelector(SELECTORS.main);
  }

  function createSidebar(options = {}) {
    let sidebar = getSidebarElement();

    if (!sidebar) {
      console.warn(
        "[WEB Course-plus] サイドバー要素がありません。" +
        "HTMLに #appSidebar または data-app-sidebar を追加してください。"
      );
      return null;
    }

    const userName = options.userName ||
      sidebar.dataset.userName ||
      "生徒";

    const menu = options.menu || APP.studentMenu;

    sidebar.classList.add("app-sidebar");

    sidebar.innerHTML = `
      <div class="app-sidebar-header">
        <div class="app-brand-mark">W</div>
        <div class="app-brand-text">
          <div>${escapeHTML(APP.name)}</div>
          <div class="app-brand-caption">生徒ポータル</div>
        </div>
      </div>

      <nav class="app-sidebar-nav" aria-label="メインメニュー">
        ${createMenuHTML(menu)}
      </nav>

      <div class="app-sidebar-footer">
        <div class="app-user-card">
          <div class="app-user-avatar">
            ${escapeHTML(getUserInitial(userName))}
          </div>
          <div class="app-user-details">
            <div class="app-user-name">${escapeHTML(userName)}</div>
            <div class="app-user-role">生徒アカウント</div>
          </div>
        </div>

        <button class="app-sidebar-logout" type="button" data-app-logout>
          <span class="app-nav-icon">${getIcon("logout")}</span>
          <span class="app-sidebar-logout-label">ログアウト</span>
        </button>
      </div>
    `;

    return sidebar;
  }

  function createTopbar(options = {}) {
    const main = getMainElement();
    if (!main) return null;

    let topbar = main.querySelector(".app-topbar");

    if (!topbar) {
      topbar = document.createElement("header");
      topbar.className = "app-topbar";
      main.prepend(topbar);
    }

    const title = options.title ||
      document.title.replace(/\s*[|｜-]\s*WEB Course-plus.*$/i, "") ||
      "WEB Course-plus";

    topbar.innerHTML = `
      <button
        class="app-menu-toggle"
        type="button"
        data-sidebar-toggle
        aria-label="メニューを開閉"
        title="メニューを開閉"
      >
        ${getIcon("menu")}
      </button>
      <div class="app-topbar-title">${escapeHTML(title)}</div>
      <div class="app-topbar-actions" data-app-topbar-actions></div>
    `;

    return topbar;
  }

  function createOverlay() {
    let overlay = document.querySelector(".app-sidebar-overlay");

    if (!overlay) {
      overlay = document.createElement("div");
      overlay.className = "app-sidebar-overlay";
      overlay.setAttribute("aria-hidden", "true");
      document.body.appendChild(overlay);
    }

    overlay.addEventListener("click", closeMobileSidebar);
    return overlay;
  }

  function isMobile() {
    return window.matchMedia("(max-width: 900px)").matches;
  }

  function toggleSidebar() {
    if (isMobile()) {
      document.body.classList.toggle("sidebar-mobile-open");
      return;
    }

    document.body.classList.toggle("sidebar-collapsed");

    const collapsed =
      document.body.classList.contains("sidebar-collapsed");

    try {
      sessionStorage.setItem(
        "web-course-plus-sidebar-collapsed",
        collapsed ? "1" : "0"
      );
    } catch {
      // ストレージが利用できない環境では保存しない
    }
  }

  function closeMobileSidebar() {
    document.body.classList.remove("sidebar-mobile-open");
  }

  function restoreSidebarState() {
    if (isMobile()) return;

    try {
      const value = sessionStorage.getItem(
        "web-course-plus-sidebar-collapsed"
      );

      document.body.classList.toggle(
        "sidebar-collapsed",
        value === "1"
      );
    } catch {
      // 初期状態のまま使用
    }
  }

  function bindSidebarEvents() {
    document.addEventListener("click", event => {
      const toggle = event.target.closest(SELECTORS.toggle);

      if (toggle) {
        event.preventDefault();
        toggleSidebar();
        return;
      }

      const logout = event.target.closest("[data-app-logout]");

      if (logout) {
        event.preventDefault();

        document.dispatchEvent(
          new CustomEvent("webcourseplus:logout-request")
        );

        return;
      }

      const link = event.target.closest(".app-nav-link");

      if (link && isMobile()) {
        closeMobileSidebar();
      }
    });

    window.addEventListener("resize", () => {
      if (!isMobile()) closeMobileSidebar();
    });
  }

  function showToast(message, options = {}) {
    let toast = document.querySelector(".app-toast");

    if (!toast) {
      toast = document.createElement("div");
      toast.className = "app-toast";
      toast.setAttribute("role", "status");
      toast.setAttribute("aria-live", "polite");
      document.body.appendChild(toast);
    }

    toast.textContent = String(message ?? "");
    toast.classList.add("visible");

    window.clearTimeout(showToast.timer);

    showToast.timer = window.setTimeout(() => {
      toast.classList.remove("visible");
    }, Number(options.duration) || 2600);
  }

  function formatDate(value, options = {}) {
    if (!value) return "-";

    const date = value instanceof Date ? value : new Date(value);

    if (Number.isNaN(date.getTime())) return "-";

    return new Intl.DateTimeFormat(
      options.locale || "ja-JP",
      options.format || {
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
      }
    ).format(date);
  }

  function formatDateTime(value) {
    return formatDate(value, {
      format: {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
      }
    });
  }

  function setPageTitle(title) {
    const element = document.querySelector(".app-topbar-title");

    if (element) {
      element.textContent = title;
    }

    document.title = `${title} | ${APP.name}`;
  }

  function setUserName(name) {
    const nameElement = document.querySelector(".app-user-name");
    const avatarElement = document.querySelector(".app-user-avatar");

    if (nameElement) nameElement.textContent = name || "生徒";
    if (avatarElement) {
      avatarElement.textContent = getUserInitial(name);
    }
  }

  function setMenuBadge(label, count) {
    const link = [...document.querySelectorAll(".app-nav-link")]
      .find(item => item.textContent.trim().includes(label));

    if (!link) return;

    const oldBadge = link.querySelector(".app-nav-badge");
    if (oldBadge) oldBadge.remove();

    const value = Number(count);

    if (!Number.isFinite(value) || value <= 0) return;

    const badge = document.createElement("span");
    badge.className = "app-nav-badge";
    badge.textContent = value > 99 ? "99+" : String(value);
    link.appendChild(badge);
  }

  function init(options = {}) {
    const sidebar = createSidebar(options);

    if (!sidebar) return false;

    const main = getMainElement();

    if (main) {
      main.classList.add("app-main");
      createTopbar(options);

      const content = main.querySelector(
        "[data-app-content], .app-content"
      );

      if (content) content.classList.add("app-content");
    }

    createOverlay();
    restoreSidebarState();
    bindSidebarEvents();

    document.dispatchEvent(
      new CustomEvent("webcourseplus:ui-ready")
    );

    return true;
  }

  // 他のページから利用できる共通API
  window.WEB_COURSE_PLUS = {
    init,
    showToast,
    formatDate,
    formatDateTime,
    setPageTitle,
    setUserName,
    setMenuBadge,
    toggleSidebar,
    closeMobileSidebar,
    icons: ICONS
  };

  // HTMLに data-auto-sidebar を付けた場合のみ自動初期化
  document.addEventListener("DOMContentLoaded", () => {
    if (document.querySelector("[data-auto-sidebar]")) {
      init();
    }
  });

})();
