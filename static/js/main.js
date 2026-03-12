(function () {
    "use strict";

    var prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // --- Nav scroll detection ---
    var header = document.getElementById("site-header");
    var scrollThreshold = 50;

    function updateHeaderScroll() {
        if (window.scrollY > scrollThreshold) {
            header.classList.add("scrolled");
        } else {
            header.classList.remove("scrolled");
        }
    }

    window.addEventListener("scroll", updateHeaderScroll, { passive: true });
    updateHeaderScroll();

    // --- Hamburger toggle ---
    var hamburger = document.getElementById("hamburger");
    var navMenu = document.getElementById("nav-menu");

    hamburger.addEventListener("click", function () {
        var isOpen = navMenu.classList.toggle("open");
        hamburger.classList.toggle("active", isOpen);
        hamburger.setAttribute("aria-expanded", String(isOpen));
    });

    // Close menu on nav link click
    var navLinks = navMenu.querySelectorAll(".nav-link");
    for (var i = 0; i < navLinks.length; i++) {
        navLinks[i].addEventListener("click", function () {
            navMenu.classList.remove("open");
            hamburger.classList.remove("active");
            hamburger.setAttribute("aria-expanded", "false");
        });
    }

    // --- Smooth scroll for anchor links ---
    var navHeight = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--nav-height")) || 64;

    document.addEventListener("click", function (e) {
        var link = e.target.closest('a[href^="#"]');
        if (!link) return;

        var targetId = link.getAttribute("href");
        if (targetId === "#") return;

        var target = document.querySelector(targetId);
        if (!target) return;

        e.preventDefault();
        var top = target.getBoundingClientRect().top + window.scrollY - navHeight;
        window.scrollTo({ top: top, behavior: prefersReducedMotion ? "auto" : "smooth" });
    });

    // --- Intersection Observer for fade-in ---
    if ("IntersectionObserver" in window && !prefersReducedMotion) {
        var fadeEls = document.querySelectorAll(".fade-in");
        var observer = new IntersectionObserver(
            function (entries) {
                for (var j = 0; j < entries.length; j++) {
                    if (entries[j].isIntersecting) {
                        entries[j].target.classList.add("visible");
                        observer.unobserve(entries[j].target);
                    }
                }
            },
            { threshold: 0.15, rootMargin: "0px 0px -40px 0px" }
        );
        for (var k = 0; k < fadeEls.length; k++) {
            observer.observe(fadeEls[k]);
        }
    } else {
        // No observer or reduced motion: show all immediately
        var allFade = document.querySelectorAll(".fade-in");
        for (var m = 0; m < allFade.length; m++) {
            allFade[m].classList.add("visible");
        }
    }

    // --- Contact form ---
    var form = document.getElementById("contact-form");
    var formStatus = document.getElementById("form-status");

    if (form) {
        form.addEventListener("submit", function (e) {
            e.preventDefault();
            formStatus.textContent = "";
            formStatus.className = "";

            var submitBtn = form.querySelector(".btn-submit");
            submitBtn.disabled = true;
            submitBtn.textContent = "Sending...";

            var data = new FormData(form);

            fetch("/contact", {
                method: "POST",
                body: data,
            })
                .then(function (resp) {
                    if (!resp.ok && resp.status !== 422) {
                        throw new Error("Server error");
                    }
                    return resp.json();
                })
                .then(function (json) {
                    if (json.status === "error") {
                        formStatus.textContent = json.message || "Please check your input.";
                        formStatus.className = "error";
                    } else if (json.message) {
                        formStatus.textContent = json.message;
                        formStatus.className = "success";
                        form.reset();
                    } else {
                        formStatus.textContent = "Message sent.";
                        formStatus.className = "success";
                        form.reset();
                    }
                })
                .catch(function () {
                    formStatus.textContent = "Something went wrong. Please try again.";
                    formStatus.className = "error";
                })
                .finally(function () {
                    submitBtn.disabled = false;
                    submitBtn.textContent = "Send Message";
                });
        });
    }
})();
