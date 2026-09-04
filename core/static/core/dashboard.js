document.addEventListener("DOMContentLoaded", () => {
    const pageLabels = {
        overview: "Visão geral",
        profile: "Meu perfil",
        access: "Controle de acessos",
        activity: "Atividades",
    };

    const showView = (name, updateHash = true) => {
        const target = document.querySelector(`[data-view="${name}"]`);
        if (!target) return;

        document.querySelectorAll("[data-view]").forEach((view) => {
            view.classList.toggle("is-visible", view === target);
        });
        document.querySelectorAll(".main-nav [data-view-target]").forEach((item) => {
            item.classList.toggle("is-active", item.dataset.viewTarget === name);
        });

        const label = document.querySelector("[data-page-label]");
        if (label) label.textContent = pageLabels[name] || pageLabels.overview;
        document.title = `${pageLabels[name] || "Dashboard"} — Orbit`;
        document.body.classList.remove("sidebar-open");
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

    const dateElement = document.querySelector("[data-current-date]");
    if (dateElement) {
        dateElement.textContent = new Intl.DateTimeFormat("pt-BR", {
            day: "2-digit",
            month: "long",
            year: "numeric",
        }).format(new Date());
    }

    document.querySelector("[data-sidebar-open]")?.addEventListener("click", () => {
        document.body.classList.add("sidebar-open");
    });
    document.querySelectorAll("[data-sidebar-close]").forEach((item) => {
        item.addEventListener("click", () => document.body.classList.remove("sidebar-open"));
    });

    const toast = document.querySelector(".toast");
    let toastTimer;
    document.querySelectorAll("[data-copy]").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(button.dataset.copy);
                toast?.classList.add("is-visible");
                clearTimeout(toastTimer);
                toastTimer = setTimeout(() => toast?.classList.remove("is-visible"), 2200);
            } catch (_error) {
                const input = document.createElement("textarea");
                input.value = button.dataset.copy;
                document.body.appendChild(input);
                input.select();
                document.execCommand("copy");
                input.remove();
            }
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

    const search = document.querySelector(".search-box input");
    document.addEventListener("keydown", (event) => {
        if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
            event.preventDefault();
            search?.focus();
        }
        if (event.key === "Escape") {
            search?.blur();
            document.body.classList.remove("sidebar-open");
        }
    });
});
