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

    // --- Scroll progress bar (nav-integrated) ---
    var navProgress = document.getElementById("nav-progress");

    function updateScrollProgress() {
        var scrollTop = window.scrollY;
        var docHeight = document.documentElement.scrollHeight - window.innerHeight;
        var progress = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
        var pct = Math.min(progress, 100);

        if (navProgress) {
            navProgress.style.width = pct + "%";
        }

        // CSS scroll-timeline fallback: set --scroll-pct for browsers without support
        if (!CSS.supports("animation-timeline", "scroll()")) {
            document.documentElement.style.setProperty("--scroll-pct", (pct / 100).toString());
        }
    }

    window.addEventListener("scroll", updateScrollProgress, { passive: true });
    updateScrollProgress();

    // --- Scroll spy (active nav link + section indicator + side rail) ---
    var navLinks = document.querySelectorAll(".nav-link");
    var scrollRailDots = document.querySelectorAll(".scroll-rail__dot");
    var scrollRail = document.getElementById("scroll-rail");
    var sections = [];
    var sectionMeta = {
        "about": { label: "About", ref: "SEC-01" },
        "defender": { label: "Defender Fabrication", ref: "SEC-02" },
        "software": { label: "Software Architecture", ref: "SEC-03" },
        "writing": { label: "Writing & Ideas", ref: "SEC-04" },
        "contact": { label: "Contact", ref: "SEC-05" }
    };

    for (var s = 0; s < navLinks.length; s++) {
        var href = navLinks[s].getAttribute("href");
        if (href && href.charAt(0) === "#") {
            var sectionEl;
            try { sectionEl = document.querySelector(href); } catch (e) { sectionEl = null; }
            if (sectionEl) {
                sections.push({ el: sectionEl, link: navLinks[s], id: href.substring(1) });
            }
        }
    }

    var sectionIndicator = document.getElementById("section-indicator");
    var sectionIndicatorLabel = document.getElementById("section-indicator-label");
    var sectionIndicatorRef = document.getElementById("section-indicator-ref");
    var currentActiveSection = null;
    var navHeight = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--nav-height")) || 72;

    function updateScrollSpy() {
        var scrollPos = window.scrollY + navHeight + 100;
        var activeSection = null;

        for (var i = sections.length - 1; i >= 0; i--) {
            if (sections[i].el.offsetTop <= scrollPos) {
                activeSection = sections[i];
                break;
            }
        }

        // Side rail visibility: show after scrolling past hero
        if (scrollRail) {
            if (window.scrollY > window.innerHeight * 0.5) {
                scrollRail.classList.add("scroll-rail--visible");
            } else {
                scrollRail.classList.remove("scroll-rail--visible");
            }
        }

        if (activeSection && activeSection.id !== currentActiveSection) {
            // Remove active from all nav links
            for (var j = 0; j < sections.length; j++) {
                sections[j].link.classList.remove("active");
            }
            activeSection.link.classList.add("active");
            currentActiveSection = activeSection.id;

            // Update side rail dots
            for (var r = 0; r < scrollRailDots.length; r++) {
                var dotHref = scrollRailDots[r].getAttribute("href");
                if (dotHref === "#" + activeSection.id) {
                    scrollRailDots[r].classList.add("scroll-rail__dot--active");
                } else {
                    scrollRailDots[r].classList.remove("scroll-rail__dot--active");
                }
            }

            // Update section indicator
            if (sectionIndicator && sectionIndicatorLabel && sectionIndicatorRef) {
                var meta = sectionMeta[activeSection.id];
                if (meta) {
                    sectionIndicatorLabel.textContent = meta.label;
                    sectionIndicatorRef.textContent = meta.ref;
                    sectionIndicator.classList.add("visible");
                }
            }
        }

        // Hide section indicator and side rail when at top of page
        if (window.scrollY < scrollThreshold) {
            if (sectionIndicator) {
                sectionIndicator.classList.remove("visible");
            }
            currentActiveSection = null;
            for (var k = 0; k < sections.length; k++) {
                sections[k].link.classList.remove("active");
            }
            for (var d = 0; d < scrollRailDots.length; d++) {
                scrollRailDots[d].classList.remove("scroll-rail__dot--active");
            }
        }
    }

    window.addEventListener("scroll", updateScrollSpy, { passive: true });
    updateScrollSpy();

    // --- Hamburger toggle ---
    var hamburger = document.getElementById("hamburger");
    var navMenu = document.getElementById("nav-menu");

    hamburger.addEventListener("click", function () {
        var isOpen = navMenu.classList.toggle("open");
        hamburger.classList.toggle("active", isOpen);
        hamburger.setAttribute("aria-expanded", String(isOpen));

        if (isOpen) {
            document.body.style.overflow = "hidden";
        } else {
            document.body.style.overflow = "";
        }
    });

    // Close menu on nav link click
    var allNavLinks = navMenu.querySelectorAll(".nav-link");
    for (var i = 0; i < allNavLinks.length; i++) {
        allNavLinks[i].addEventListener("click", function () {
            navMenu.classList.remove("open");
            hamburger.classList.remove("active");
            hamburger.setAttribute("aria-expanded", "false");
            document.body.style.overflow = "";
        });
    }

    // Close menu on Escape key
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && navMenu.classList.contains("open")) {
            navMenu.classList.remove("open");
            hamburger.classList.remove("active");
            hamburger.setAttribute("aria-expanded", "false");
            document.body.style.overflow = "";
            hamburger.focus();
        }
    });

    // --- Smooth scroll for anchor links ---
    document.addEventListener("click", function (e) {
        var link = e.target.closest('a[href^="#"]');
        if (!link) return;

        var targetId = link.getAttribute("href");
        if (targetId === "#") return;

        var target;
        try { target = document.querySelector(targetId); } catch (e) { return; }
        if (!target) return;

        e.preventDefault();
        var scrollNavHeight = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--nav-height")) || 72;
        var top = target.getBoundingClientRect().top + window.scrollY - scrollNavHeight;
        window.scrollTo({ top: top, behavior: prefersReducedMotion ? "auto" : "smooth" });
    });


    // =================================================================
    // SECTION REVEAL SYSTEM
    // Replaces generic .fade-in with section-specific reveals.
    // Uses IntersectionObserver to trigger .revealed class.
    // =================================================================

    if ("IntersectionObserver" in window && !prefersReducedMotion) {

        // --- Section-specific reveal observer ---
        var revealEls = document.querySelectorAll(".reveal-ready");
        var revealObserver = new IntersectionObserver(
            function (entries) {
                for (var j = 0; j < entries.length; j++) {
                    if (entries[j].isIntersecting) {
                        entries[j].target.classList.add("revealed");
                        revealObserver.unobserve(entries[j].target);
                    }
                }
            },
            { threshold: 0.12, rootMargin: "0px 0px -60px 0px" }
        );

        for (var k = 0; k < revealEls.length; k++) {
            revealObserver.observe(revealEls[k]);
        }

        // --- Legacy .fade-in support (for any remaining elements) ---
        var fadeEls = document.querySelectorAll(".fade-in");
        if (fadeEls.length > 0) {
            var fadeObserver = new IntersectionObserver(
                function (entries) {
                    for (var j = 0; j < entries.length; j++) {
                        if (entries[j].isIntersecting) {
                            entries[j].target.classList.add("visible");
                            fadeObserver.unobserve(entries[j].target);
                        }
                    }
                },
                { threshold: 0.15, rootMargin: "0px 0px -40px 0px" }
            );
            for (var f = 0; f < fadeEls.length; f++) {
                fadeObserver.observe(fadeEls[f]);
            }
        }

    } else {
        // No observer or reduced motion: show all immediately
        var allReveal = document.querySelectorAll(".reveal-ready");
        for (var m = 0; m < allReveal.length; m++) {
            allReveal[m].classList.add("revealed");
        }
        var allFade = document.querySelectorAll(".fade-in");
        for (var n = 0; n < allFade.length; n++) {
            allFade[n].classList.add("visible");
        }
    }


    // =================================================================
    // STAT NUMBER COUNT-UP
    // Numbers animate from 0 to their data-count value when they
    // enter the viewport. Mechanical, linear ramp -- not eased.
    // =================================================================

    if ("IntersectionObserver" in window && !prefersReducedMotion) {
        var countEls = document.querySelectorAll(".stat-number[data-count]");

        var countObserver = new IntersectionObserver(
            function (entries) {
                for (var c = 0; c < entries.length; c++) {
                    if (entries[c].isIntersecting) {
                        animateCount(entries[c].target);
                        countObserver.unobserve(entries[c].target);
                    }
                }
            },
            { threshold: 0.5 }
        );

        for (var ci = 0; ci < countEls.length; ci++) {
            countObserver.observe(countEls[ci]);
        }
    } else {
        // Reduced motion or no observer: show final values immediately
        var staticCounts = document.querySelectorAll(".stat-number[data-count]");
        for (var sc = 0; sc < staticCounts.length; sc++) {
            var finalVal = staticCounts[sc].getAttribute("data-count");
            var suffix = staticCounts[sc].getAttribute("data-suffix") || "";
            staticCounts[sc].textContent = finalVal + suffix;
        }
    }

    function animateCount(el) {
        var target = parseInt(el.getAttribute("data-count"), 10);
        var suffix = el.getAttribute("data-suffix") || "";
        var duration = 800; // ms -- brisk mechanical ramp
        var startTime = null;

        el.classList.add("stat-number--counting");

        function step(timestamp) {
            if (!startTime) startTime = timestamp;
            var elapsed = timestamp - startTime;
            var progress = Math.min(elapsed / duration, 1);

            // Linear ramp -- mechanical, not eased
            var current = Math.floor(progress * target);
            el.textContent = current + suffix;

            if (progress < 1) {
                requestAnimationFrame(step);
            } else {
                el.textContent = target + suffix;
                el.classList.remove("stat-number--counting");
            }
        }

        requestAnimationFrame(step);
    }


    // =================================================================
    // 3D CARD TILT (mouse-position tracking)
    // Sets --tilt-x, --tilt-y custom properties consumed by depth.css.
    // Max rotation: 6 degrees. GPU-composited transforms only.
    // =================================================================

    if (!prefersReducedMotion) {
        var tiltCards = document.querySelectorAll(".defender-card, .software-card");
        var MAX_TILT = 6;

        for (var t = 0; t < tiltCards.length; t++) {
            (function (card) {
                card.addEventListener("mousemove", function (e) {
                    var rect = card.getBoundingClientRect();
                    var x = (e.clientX - rect.left) / rect.width;
                    var y = (e.clientY - rect.top) / rect.height;
                    var tiltY = (x - 0.5) * 2 * MAX_TILT;
                    var tiltX = (0.5 - y) * 2 * MAX_TILT;

                    requestAnimationFrame(function () {
                        card.style.setProperty("--tilt-x", tiltX + "deg");
                        card.style.setProperty("--tilt-y", tiltY + "deg");
                        card.style.setProperty("--tilt-scale", "1.02");
                    });
                });

                card.addEventListener("mouseleave", function () {
                    requestAnimationFrame(function () {
                        card.style.setProperty("--tilt-x", "0deg");
                        card.style.setProperty("--tilt-y", "0deg");
                        card.style.setProperty("--tilt-scale", "1");
                    });
                });
            })(tiltCards[t]);
        }
    }


    // =================================================================
    // FONT LOADING (FOUT management)
    // Adds .fonts-loading during load, swaps to .fonts-loaded when ready.
    // Falls back after 3s for progressive enhancement.
    // =================================================================

    document.body.classList.add("fonts-loading");

    var fontTimeout = setTimeout(function () {
        document.body.classList.remove("fonts-loading");
        document.body.classList.add("fonts-loaded");
    }, 3000);

    if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(function () {
            clearTimeout(fontTimeout);
            requestAnimationFrame(function () {
                document.body.classList.remove("fonts-loading");
                document.body.classList.add("fonts-loaded");
            });
        });
    }


    // =================================================================
    // CONTACT FORM
    // =================================================================

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
                headers: { "X-Requested-With": "XMLHttpRequest" },
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
