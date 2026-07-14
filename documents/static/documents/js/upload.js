(() => {
    "use strict";

    const form = document.querySelector("[data-upload-form]");
    const input = document.querySelector("[data-upload-input]");
    const dropzone = document.querySelector("[data-dropzone]");
    const selected = document.querySelector("[data-selected-file]");
    const submit = document.querySelector("[data-submit-button]");

    if (!form || !input || !dropzone || !selected) return;

    function formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes <= 0) return "0 bytes";
        const units = ["bytes", "KB", "MB", "GB"];
        const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        const value = bytes / Math.pow(1024, index);
        return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
    }

    function showFile() {
        const file = input.files && input.files[0];
        if (!file) {
            selected.textContent = "No file selected";
            dropzone.classList.remove("has-file");
            return;
        }
        selected.textContent = `${file.name} - ${formatBytes(file.size)}`;
        dropzone.classList.add("has-file");
    }

    input.addEventListener("change", showFile);

    ["dragenter", "dragover"].forEach((name) => {
        dropzone.addEventListener(name, (event) => {
            event.preventDefault();
            dropzone.classList.add("is-dragging");
        });
    });

    ["dragleave", "drop"].forEach((name) => {
        dropzone.addEventListener(name, (event) => {
            event.preventDefault();
            dropzone.classList.remove("is-dragging");
        });
    });

    dropzone.addEventListener("drop", (event) => {
        const files = event.dataTransfer && event.dataTransfer.files;
        if (!files || !files.length) return;
        try {
            const transfer = new DataTransfer();
            transfer.items.add(files[0]);
            input.files = transfer.files;
            showFile();
        } catch (error) {
            selected.textContent = "Please use Choose document to select this file.";
        }
    });

    form.addEventListener("submit", () => {
        if (!submit) return;
        submit.disabled = true;
        const text = submit.querySelector("span:first-child");
        if (text) text.textContent = "Encrypting and uploading...";
    });
})();
