(() => {
    const menu = document.querySelector(".menu-toggle");
    const navigation = document.querySelector(".main-navigation");
    if (menu && navigation) {
        menu.hidden = false;
        document.body.classList.add("menu-ready");
        const closeMenu = () => {
            document.body.classList.remove("menu-open");
            menu.setAttribute("aria-expanded", "false");
            menu.setAttribute("aria-label", "Abrir navegação");
        };
        menu.addEventListener("click", () => {
            const open = document.body.classList.toggle("menu-open");
            menu.setAttribute("aria-expanded", String(open));
            menu.setAttribute("aria-label", open ? "Fechar navegação" : "Abrir navegação");
        });
        navigation.querySelectorAll("a").forEach(link => link.addEventListener("click", closeMenu));
        document.addEventListener("keydown", event => {
            if (event.key === "Escape" && document.body.classList.contains("menu-open")) {
                closeMenu();
                menu.focus();
            }
        });
        document.addEventListener("click", event => {
            if (!event.target.closest(".masthead")) closeMenu();
        });
        window.matchMedia("(min-width: 761px)").addEventListener("change", closeMenu);
    }

    const solutions = [...document.querySelectorAll("[data-solution]")];
    const visual = document.querySelector("[data-visual]");
    const label = document.querySelector("[data-visual-label]");
    const labels = {
        identity: "Uma identidade. Todas as conexões.",
        security: "Os acessos certos. Nos lugares certos.",
        connection: "Pessoas e possibilidades em sintonia.",
    };
    solutions.forEach(solution => {
        solution.addEventListener("toggle", () => {
            if (!solution.open) return;
            solutions.forEach(other => { if (other !== solution) other.open = false; });
            if (visual) visual.dataset.visual = solution.dataset.solution;
            if (label) label.textContent = labels[solution.dataset.solution];
        });
    });
})();
