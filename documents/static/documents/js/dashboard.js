(() => {
    "use strict";

    const modal = document.querySelector("[data-modal]");
    const openButton = document.querySelector("[data-open-modal]");
    const closeButtons = document.querySelectorAll("[data-close-modal]");
    const requestForm = document.querySelector("[data-new-request-form]");
    const documentType = document.querySelector("[data-document-type]");
    const otherGroup = document.querySelector("[data-other-document-group]");
    const tableHost = document.querySelector("#requests-table");
    const searchInput = document.querySelector("[data-request-search]");
    const filterButtons = Array.from(document.querySelectorAll("[data-status-filter]"));
    let lastFocused = null;
    let searchTimer = null;
    let tableRequest = null;

    const focusableSelector = "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

    function setOtherVisibility() {
        if (!documentType || !otherGroup) return;
        otherGroup.hidden = documentType.value !== "other";
        if (otherGroup.hidden) {
            const input = otherGroup.querySelector("input");
            if (input) input.value = "";
        }
    }

    function clearFormErrors() {
        document.querySelectorAll("[data-error-for]").forEach((node) => {
            node.textContent = "";
        });
        const alert = document.querySelector("[data-form-alert]");
        if (alert) {
            alert.textContent = "";
            alert.hidden = true;
        }
    }

    function openModal() {
        if (!modal) return;
        lastFocused = document.activeElement;
        modal.hidden = false;
        document.body.classList.add("modal-open");
        clearFormErrors();
        setOtherVisibility();
        const firstInput = modal.querySelector("input:not([type='hidden'])");
        if (firstInput) firstInput.focus();
    }

    function closeModal() {
        if (!modal) return;
        modal.hidden = true;
        document.body.classList.remove("modal-open");
        if (lastFocused instanceof HTMLElement) lastFocused.focus();
    }

    if (openButton) openButton.addEventListener("click", openModal);
    closeButtons.forEach((button) => button.addEventListener("click", closeModal));
    if (documentType) documentType.addEventListener("change", setOtherVisibility);

    if (modal) {
        modal.addEventListener("mousedown", (event) => {
            if (event.target === modal) closeModal();
        });
        modal.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                closeModal();
                return;
            }
            if (event.key !== "Tab") return;
            const focusable = Array.from(modal.querySelectorAll(focusableSelector));
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        });
    }

    function setSubmitting(isSubmitting) {
        const button = document.querySelector("[data-create-submit]");
        if (!button) return;
        button.disabled = isSubmitting;
        const text = button.querySelector("span:first-child");
        if (text) text.textContent = isSubmitting ? "Sending..." : "Send request";
    }

    if (requestForm) {
        requestForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            clearFormErrors();
            setSubmitting(true);
            try {
                const response = await fetch(requestForm.action, {
                    method: "POST",
                    body: new FormData(requestForm),
                    credentials: "same-origin",
                    headers: { Accept: "application/json" },
                });
                const payload = await response.json();
                if (payload.ok) {
                    window.location.assign(payload.redirect);
                    return;
                }
                if (payload.errors) {
                    Object.entries(payload.errors).forEach(([field, messages]) => {
                        const target = document.querySelector(`[data-error-for="${CSS.escape(field)}"]`);
                        if (target) target.textContent = messages.join(" ");
                    });
                }
                const alert = document.querySelector("[data-form-alert]");
                if (alert && payload.message) {
                    alert.textContent = payload.message;
                    alert.hidden = false;
                }
            } catch (error) {
                const alert = document.querySelector("[data-form-alert]");
                if (alert) {
                    alert.textContent = "The request could not be sent. Check your connection and try again.";
                    alert.hidden = false;
                }
            } finally {
                setSubmitting(false);
            }
        });
    }

    function currentStatus() {
        const active = filterButtons.find((button) => button.classList.contains("is-active"));
        return active ? active.dataset.statusFilter : "all";
    }

    async function loadTable(page = "1", updateHistory = true) {
        if (!tableHost || !searchInput) return;
        if (tableRequest) tableRequest.abort();
        tableRequest = new AbortController();
        const params = new URLSearchParams({
            q: searchInput.value.trim(),
            status: currentStatus(),
            page,
        });
        const url = `${tableHost.dataset.tableUrl}?${params.toString()}`;
        tableHost.setAttribute("aria-busy", "true");
        try {
            const response = await fetch(url, {
                credentials: "same-origin",
                headers: { "X-Requested-With": "XMLHttpRequest" },
                signal: tableRequest.signal,
            });
            if (!response.ok) throw new Error("Unable to load requests");
            tableHost.innerHTML = await response.text();
            if (updateHistory) {
                const browserUrl = new URL(window.location.href);
                browserUrl.search = params.toString();
                window.history.replaceState({}, "", browserUrl);
            }
        } catch (error) {
            if (error.name !== "AbortError") {
                tableHost.textContent = "Unable to load requests. Refresh the page to try again.";
            }
        } finally {
            tableHost.removeAttribute("aria-busy");
        }
    }

    if (searchInput) {
        searchInput.addEventListener("input", () => {
            window.clearTimeout(searchTimer);
            searchTimer = window.setTimeout(() => loadTable("1"), 280);
        });
    }

    filterButtons.forEach((button) => {
        button.addEventListener("click", () => {
            filterButtons.forEach((item) => item.classList.remove("is-active"));
            button.classList.add("is-active");
            loadTable("1");
        });
    });

    if (tableHost) {
        tableHost.addEventListener("click", (event) => {
            const link = event.target.closest("[data-page-link]");
            if (!link) return;
            event.preventDefault();
            const url = new URL(link.href);
            loadTable(url.searchParams.get("page") || "1");
        });
    }

    document.addEventListener("submit", (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement) || !form.dataset.confirm) return;
        if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });

    setOtherVisibility();
})();
