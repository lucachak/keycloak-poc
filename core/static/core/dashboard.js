document.addEventListener("DOMContentLoaded", () => {
    const pageLabels = {
        overview: "Visão geral",
        profile: "Identidade",
        access: "Acessos",
        activity: "Atividade",
    };

    const closeMenu = () => {
        document.body.classList.remove("menu-open");
        document.querySelector("[data-menu-toggle]")?.setAttribute("aria-expanded", "false");
    };

    const showView = (name, updateHash = true) => {
        const target = document.querySelector(`[data-view="${name}"]`);
        if (!target) return;

        document.querySelectorAll("[data-view]").forEach((view) => {
            view.classList.toggle("is-visible", view === target);
        });
        document.querySelectorAll(".desktop-nav [data-view-target]").forEach((item) => {
            item.classList.toggle("is-active", item.dataset.viewTarget === name);
        });

        document.title = `${pageLabels[name] || "Orbit"} — Orbit`;
        closeMenu();
        window.scrollTo({ top: 0, behavior: "smooth" });
        if (updateHash) history.replaceState(null, "", name === "overview" ? window.location.pathname : `#${name}`);
    };

    document.querySelectorAll("[data-view-target]").forEach((item) => {
        item.addEventListener("click", () => showView(item.dataset.viewTarget));
    });

    const initialView = window.location.hash.replace("#", "");
    if (pageLabels[initialView]) showView(initialView, false);

    const getInitials = (name) => {
        const parts = String(name || "U").trim().split(/\s+/).filter(Boolean);
        return `${parts[0]?.[0] || "U"}${parts.length > 1 ? parts.at(-1)[0] : ""}`.toUpperCase();
    };
    document.querySelectorAll("[data-avatar-name]").forEach((avatar) => {
        avatar.textContent = getInitials(avatar.dataset.avatarName);
    });

    document.querySelectorAll("[data-current-date]").forEach((element) => {
        element.textContent = new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "short", year: "numeric" }).format(new Date());
    });

    document.querySelector("[data-menu-toggle]")?.addEventListener("click", (event) => {
        const isOpen = document.body.classList.toggle("menu-open");
        event.currentTarget.setAttribute("aria-expanded", String(isOpen));
    });

    const toast = document.querySelector(".toast");
    let toastTimer;
    document.querySelectorAll("[data-copy]").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(button.dataset.copy || "");
            } catch (_error) {
                const field = document.createElement("textarea");
                field.value = button.dataset.copy || "";
                document.body.appendChild(field);
                field.select();
                document.execCommand("copy");
                field.remove();
            }
            toast?.classList.add("is-visible");
            clearTimeout(toastTimer);
            toastTimer = setTimeout(() => toast?.classList.remove("is-visible"), 1800);
        });
    });

    document.querySelectorAll("[data-filter]").forEach((button) => {
        button.addEventListener("click", () => {
            const filter = button.dataset.filter;
            document.querySelectorAll("[data-filter]").forEach((item) => item.classList.toggle("is-active", item === button));
            document.querySelectorAll("[data-activity-kind]").forEach((item) => {
                item.classList.toggle("is-hidden", filter !== "all" && item.dataset.activityKind !== filter);
            });
        });
    });

    window.addEventListener("hashchange", () => {
        const view = window.location.hash.replace("#", "");
        if (pageLabels[view]) showView(view, false);
    });
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeMenu();
    });
});
