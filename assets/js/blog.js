// blog-4.js
// Handles code copy buttons, flag copy buttons, TOC highlighting, and collapsible code blocks

// Copy text from a code block
function copyCode(button) {
    const codeBlock = button.closest(".code-container").querySelector("pre code");
    if (!codeBlock) return;

    const text = codeBlock.innerText.trim();
    navigator.clipboard.writeText(text).then(() => {
        button.classList.add("copied");
        button.querySelector("span").innerText = "Copied!";
        setTimeout(() => {
            button.classList.remove("copied");
            button.querySelector("span").innerText = "Copy";
        }, 2000);
    });
}

// Copy flag text
function copyFlag(button) {
    const flagText = button.closest(".flag-container").querySelector(".flag-text");
    if (!flagText) return;

    navigator.clipboard.writeText(flagText.innerText.trim()).then(() => {
        button.classList.add("copied");
        button.querySelector("span").innerText = "Copied!";
        setTimeout(() => {
            button.classList.remove("copied");
            button.querySelector("span").innerText = "Copy";
        }, 2000);
    });
}

// Highlight active section in TOC
function initTOCHighlighting() {
    const tocLinks = document.querySelectorAll(".toc-link");
    const sections = Array.from(tocLinks).map(link => {
        const id = link.getAttribute("href").substring(1);
        return document.getElementById(id);
    });

    function onScroll() {
        let index = sections.length;
        while (--index && window.scrollY + 150 < sections[index].offsetTop) {}
        tocLinks.forEach(link => link.classList.remove("active"));
        tocLinks[index]?.classList.add("active");
    }

    window.addEventListener("scroll", onScroll);
    onScroll();
}

// Toggle collapsible code blocks
function initCodeToggles() {
    document.querySelectorAll(".code-toggle").forEach(toggle => {
        toggle.addEventListener("click", () => {
            const container = toggle.closest(".code-container");
            container.classList.toggle("collapsed");
        });
    });
}

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    initTOCHighlighting();
    initCodeToggles();
});
