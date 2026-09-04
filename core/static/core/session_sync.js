document.addEventListener("DOMContentLoaded", () => {
    const syncIntervalMs = 15_000;
    const lockKey = "orbit-role-sync-at";

    const cookie = (name) => document.cookie
        .split(";")
        .map((item) => item.trim())
        .find((item) => item.startsWith(`${name}=`))
        ?.split("=")
        .slice(1)
        .join("=");

    const synchronize = async () => {
        if (document.hidden) return;

        const lastSync = Number(localStorage.getItem(lockKey) || 0);
        if (Date.now() - lastSync < syncIntervalMs - 500) return;
        localStorage.setItem(lockKey, String(Date.now()));

        try {
            const response = await fetch("/api/session/sync/", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Accept": "application/json",
                    "X-CSRFToken": decodeURIComponent(cookie("csrftoken") || ""),
                },
            });
            if (response.status === 401) {
                window.location.assign("/login/");
                return;
            }
            if (!response.ok) return;

            const result = await response.json();
            if (result.changed) window.location.assign("/");
        } catch (_error) {
            // A transient identity-provider failure must not break the page.
        }
    };

    window.setInterval(synchronize, syncIntervalMs);
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) synchronize();
    });
});
