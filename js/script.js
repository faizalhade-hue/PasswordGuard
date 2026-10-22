
/* ==========================================
   PasswordGuard
   ملف JavaScript الموحد لجميع الصفحات
========================================== */

"use strict";

// دالة مختصرة للعثور على عنصر داخل الصفحة
function getElement(id) {
    return document.getElementById(id);
}

// عرض الرسائل للمستخدم
function showMessage(id, message, success = false) {
    const element = getElement(id);

    if (!element) return;

    element.textContent = message;
    element.style.color = success ? "#22c55e" : "#f87171";
}

// ==========================================
// 1. تحليل قوة كلمة المرور
// ==========================================

const analyzerForm = getElement("analyzer-form");

if (analyzerForm) {
    const passwordInput = getElement("password-input");
    const showPassword = getElement("show-password");
    const resultBox = getElement("analysis-result");
    const strengthLabel = getElement("strength-label");
    const strengthBar = getElement("strength-bar");
    const feedbackList = getElement("analysis-feedback");

    // إظهار كلمة المرور أو إخفاؤها
    if (showPassword && passwordInput) {
        showPassword.addEventListener("change", function () {
            passwordInput.type = this.checked
                ? "text"
                : "password";
        });
    }

    analyzerForm.addEventListener("submit", function (event) {
        event.preventDefault();

        const password = passwordInput.value;

        if (!password) {
            alert("الرجاء إدخال كلمة المرور أولاً.");
            return;
        }

        let score = 0;
        const feedback = [];

        // فحص طول كلمة المرور
        if (password.length >= 8) {
            score++;
        } else {
            feedback.push("اجعل كلمة المرور 8 أحرف على الأقل.");
        }

        if (password.length >= 12) {
            score++;
        } else {
            feedback.push("يفضل استخدام 12 حرفاً أو أكثر.");
        }

        // فحص الأحرف الصغيرة والكبيرة
        if (/[a-z]/.test(password)) {
            score++;
        } else {
            feedback.push("يمكنك إضافة أحرف إنجليزية صغيرة.");
        }

        if (/[A-Z]/.test(password)) {
            score++;
        } else {
            feedback.push("يمكنك إضافة أحرف إنجليزية كبيرة.");
        }

        // فحص الأرقام والرموز
        if (/[0-9]/.test(password)) {
            score++;
        } else {
            feedback.push("إضافة أرقام قد تزيد التنوع.");
        }

        if (/[^a-zA-Z0-9]/.test(password)) {
            score++;
        } else {
            feedback.push("يمكنك إضافة رموز خاصة.");
        }

        // اكتشاف بعض الأنماط الشائعة
        const commonPatterns = [
            "123456",
            "password",
            "qwerty",
            "111111",
            "12345678"
        ];

        if (
            commonPatterns.some(pattern =>
                password.toLowerCase().includes(pattern)
            )
        ) {
            score = Math.min(score, 1);
            feedback.push(
                "تجنب كلمات المرور الشائعة أو التسلسلات السهلة."
            );
        }

        // تحديد مستوى القوة
        let level;
        let percentage;

        if (score <= 2) {
            level = "ضعيفة";
            percentage = 25;
        } else if (score <= 4) {
            level = "متوسطة";
            percentage = 60;
        } else {
            level = "جيدة حسب الفحوص الأساسية";
            percentage = 100;
        }

        strengthLabel.textContent =
            "مستوى كلمة المرور: " + level;

        strengthBar.style.width = percentage + "%";

        // عرض الملاحظات
        feedbackList.replaceChildren();

        if (feedback.length === 0) {
            const item = document.createElement("li");
            item.textContent =
                "اجتازت كلمة المرور الفحوص الأساسية. هذا لا يضمن أنها آمنة تماماً.";
            feedbackList.appendChild(item);
        } else {
            feedback.forEach(function (message) {
                const item = document.createElement("li");
                item.textContent = message;
                feedbackList.appendChild(item);
            });
        }

        resultBox.hidden = false;
    });
}

// ==========================================
// 2. إنشاء حساب
// ==========================================

const registerForm = getElement("register-form");

if (registerForm) {
    registerForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const name = getElement("register-name").value.trim();
        const email = getElement("register-email").value
            .trim()
            .toLowerCase();

        const password = getElement("register-password").value;
        const confirmPassword = getElement("confirm-password").value;

        if (!name || !email || !password || !confirmPassword) {
            showMessage(
                "register-message",
                "الرجاء تعبئة جميع الحقول."
            );
            return;
        }

        if (password.length < 12) {
            showMessage(
                "register-message",
                "استخدم كلمة مرور لا تقل عن 12 حرفاً."
            );
            return;
        }

        if (password !== confirmPassword) {
            showMessage(
                "register-message",
                "كلمتا المرور غير متطابقتين."
            );
            return;
        }

        // هذا النموذج يحتاج إلى Web Crypto لتجزئة كلمة المرور.
        // تخزين الحساب في المتصفح للتجربة ليس نظام تسجيل آمنًا.
        if (!window.crypto || !window.crypto.subtle) {
            showMessage(
                "register-message",
                "التشفير غير متاح في المعاينة الحالية. افتح المشروع في سياق آمن."
            );
            return;
        }

        try {
            const storageKey = "pg_account_" + email;

            if (localStorage.getItem(storageKey)) {
                showMessage(
                    "register-message",
                    "يوجد حساب تجريبي بهذا البريد بالفعل."
                );
                return;
            }

            const salt = crypto.getRandomValues(
                new Uint8Array(16)
            );

            const encoder = new TextEncoder();

            const keyMaterial = await crypto.subtle.importKey(
                "raw",
                encoder.encode(password),
                "PBKDF2",
                false,
                ["deriveBits"]
            );

            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: 100000,
                    hash: "SHA-256"
                },
                keyMaterial,
                256
            );

            const saltHex = Array.from(salt)
                .map(byte => byte.toString(16).padStart(2, "0"))
                .join("");

            const hashHex = Array.from(
                new Uint8Array(derivedBits)
            )
                .map(byte => byte.toString(16).padStart(2, "0"))
                .join("");

            const account = {
                name: name,
                salt: saltHex,
                hash: hashHex
            };

            localStorage.setItem(
                storageKey,
                JSON.stringify(account)
            );

            showMessage(
                "register-message",
                "تم إنشاء الحساب التجريبي! انتقل إلى تسجيل الدخول.",
                true
            );

            setTimeout(function () {
                window.location.href = "login.html";
            }, 1200);

        } catch (error) {
            showMessage(
                "register-message",
                "تعذر إنشاء الحساب التجريبي. حاول مرة أخرى."
            );
        }
    });
}

// ==========================================
// 3. تسجيل الدخول
// ==========================================

const loginForm = getElement("login-form");

if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const email = getElement("login-email").value
            .trim()
            .toLowerCase();

        const password = getElement("login-password").value;

        if (!email || !password) {
            showMessage(
                "login-message",
                "أدخل البريد الإلكتروني وكلمة المرور."
            );
            return;
        }

        if (!window.crypto || !window.crypto.subtle) {
            showMessage(
                "login-message",
                "التشفير غير متاح في المعاينة الحالية."
            );
            return;
        }

        try {
            const storageKey = "pg_account_" + email;
            const savedAccount = localStorage.getItem(storageKey);

            if (!savedAccount) {
                showMessage(
                    "login-message",
                    "لا يوجد حساب تجريبي بهذا البريد. أنشئ حساباً أولاً."
                );
                return;
            }

            const account = JSON.parse(savedAccount);

            const salt = new Uint8Array(
                account.salt.match(/.{2}/g).map(byte =>
                    parseInt(byte, 16)
                )
            );

            const encoder = new TextEncoder();

            const keyMaterial = await crypto.subtle.importKey(
                "raw",
                encoder.encode(password),
                "PBKDF2",
                false,
                ["deriveBits"]
            );

            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: 100000,
                    hash: "SHA-256"
                },
                keyMaterial,
                256
            );

            const enteredHash = Array.from(
                new Uint8Array(derivedBits)
            )
                .map(byte => byte.toString(16).padStart(2, "0"))
                .join("");

            if (enteredHash !== account.hash) {
                showMessage(
                    "login-message",
                    "البريد الإلكتروني أو كلمة المرور غير صحيحة."
                );
                return;
            }

            // إنشاء حالة دخول تجريبية للجلسة الحالية.
            // لا نضع كلمة المرور في بيانات الجلسة.
            sessionStorage.setItem("pg_logged_in", "true");
            sessionStorage.setItem("pg_user_email", email);
          const accountData = JSON.parse(
    localStorage.getItem("pg_account_" + email)
);

if (accountData) {
    sessionStorage.setItem(
        "pg_user_name",
        accountData.name || ""
    );
}

            showMessage(
                "login-message",
                "تم تسجيل الدخول التجريبي بنجاح. جارٍ فتح صفحة التحليل...",
                true
            );

            // لا نذهب إلى الصفحة الرئيسية بعد تسجيل الدخول.
            setTimeout(function () {
                window.location.href = "analyze.html";
            }, 800);

        } catch (error) {
            showMessage(
                "login-message",
                "حدث خطأ أثناء تسجيل الدخول. حاول مرة أخرى."
            );
        }
    });
}

// ==========================================
// 4. تواصل معنا
// ==========================================

const contactForm = getElement("contact-form");

if (contactForm) {
    contactForm.addEventListener("submit", function (event) {
        event.preventDefault();

        const name = getElement("contact-name").value.trim();
        const email = getElement("contact-email").value.trim();
        const subject = getElement("contact-subject").value.trim();
        const message = getElement("contact-message").value.trim();

        if (!name || !email || !subject || !message) {
            showMessage(
                "contact-status",
                "الرجاء تعبئة جميع الحقول."
            );
            return;
        }

        showMessage(
            "contact-status",
            "تم التحقق من الرسالة بنجاح. هذه تجربة فقط؛ لم يتم إرسال الرسالة فعلياً.",
            true
        );

        contactForm.reset();
    });
}

// ==========================================
// 5. معلومات المستخدم وتسجيل الخروج
// ==========================================

/* ========================================
   حماية صفحات PasswordGuard
======================================== */

(function () {
    const currentPage =
        window.location.pathname.split("/").pop() || "index.html";

    // الصفحات المتاحة بدون تسجيل دخول
    const publicPages = [
        "login.html",
        "register.html"
    ];

    const isLoggedIn =
        sessionStorage.getItem("pg_logged_in") === "true";

    // منع فتح الصفحات المحمية بدون تسجيل دخول
    if (!publicPages.includes(currentPage) && !isLoggedIn) {
        window.location.replace("login.html");
        return;
    }

    // منع الرجوع للصفحات المحمية بعد تسجيل الخروج
    if (isLoggedIn && publicPages.includes(currentPage)) {
        // نسمح بفتح تسجيل الدخول وإنشاء الحساب
        // حتى يستطيع المستخدم الانتقال بينهما عند الحاجة.
    }
})();

// هذه الدالة يمكن استخدامها لاحقًا في صفحة محمية.
function isLoggedIn() {
    return sessionStorage.getItem("pg_logged_in") === "true";
}

// تسجيل الخروج من الجلسة التجريبية
function logout() {
    sessionStorage.removeItem("pg_logged_in");
    sessionStorage.removeItem("pg_user_email");

    window.location.href = "login.html";
}

// ==========================================
// نهاية ملف PasswordGuard
// ==========================================


/* ========================================
   PasswordGuard - تسجيل الخروج
   وإظهار وإخفاء كلمة المرور
======================================== */

document.addEventListener("DOMContentLoaded", function () {

    // 1. إضافة زر تسجيل الخروج في جميع الصفحات
    
const navbar = document.querySelector(".navbar");
const currentPage = window.location.pathname.split("/").pop();

const hideLogoutPages = [
    "login.html",
    "register.html"
];

if (
    navbar &&
    !hideLogoutPages.includes(currentPage) &&
    !document.getElementById("logout-button")
) {
    const logoutButton = document.createElement("button");

    logoutButton.id = "logout-button";
    logoutButton.type = "button";
    logoutButton.className = "btn btn-outline logout-button";
    logoutButton.textContent = "تسجيل الخروج";

    logoutButton.addEventListener("click", function () {
        sessionStorage.removeItem("pg_logged_in");
        sessionStorage.removeItem("pg_user_email");

        window.location.href = "login.html";
    });

    navbar.appendChild(logoutButton);
}


    // 2. إضافة زر العين لحقول كلمة المرور
    const passwordFields = [
        "login-password",
        "register-password",
        "confirm-password"
    ];

    passwordFields.forEach(function (fieldId) {
        const passwordInput = document.getElementById(fieldId);

        if (!passwordInput || passwordInput.dataset.eyeAdded) {
            return;
        }

        passwordInput.dataset.eyeAdded = "true";

        // إنشاء حاوية لحقل كلمة المرور
        const wrapper = document.createElement("div");
        wrapper.className = "password-field";

        passwordInput.parentNode.insertBefore(
            wrapper,
            passwordInput
        );

        wrapper.appendChild(passwordInput);

        // إنشاء زر العين
        const eyeButton = document.createElement("button");
        eyeButton.type = "button";
        eyeButton.className = "password-eye";
        eyeButton.textContent = "👁";
        eyeButton.setAttribute("aria-label", "إظهار كلمة المرور");
        eyeButton.setAttribute("aria-pressed", "false");

        wrapper.appendChild(eyeButton);

        // إظهار أو إخفاء كلمة المرور
        eyeButton.addEventListener("click", function () {
            const isHidden = passwordInput.type === "password";

            passwordInput.type = isHidden ? "text" : "password";
            eyeButton.textContent = isHidden ? "🙈" : "👁";

            eyeButton.setAttribute(
                "aria-label",
                isHidden ? "إخفاء كلمة المرور" : "إظهار كلمة المرور"
            );

            eyeButton.setAttribute(
                "aria-pressed",
                String(isHidden)
            );
        });
    });

});

/* ========================================
   عرض بيانات الحساب في الملف الشخصي
======================================== */

document.addEventListener("DOMContentLoaded", function () {
    const profileForm = document.getElementById("profile-form");

    if (!profileForm) return;

    const emailInput = document.getElementById("profile-email");
    const nameInput = document.getElementById("profile-name");
    const heading = document.getElementById("profile-heading");
    const message = document.getElementById("profile-message");

    const email = sessionStorage.getItem("pg_user_email");

    if (!email || sessionStorage.getItem("pg_logged_in") !== "true") {
        window.location.replace("login.html");
        return;
    }

    let account;

    try {
        account = JSON.parse(
            localStorage.getItem("pg_account_" + email)
        );
    } catch (error) {
        account = null;
    }

    if (!account) {
        message.textContent = "لم يتم العثور على بيانات الحساب.";
        return;
    }

    nameInput.value = account.name || "";
    emailInput.value = email;
    heading.textContent = account.name || "حسابي";

    profileForm.addEventListener("submit", function (event) {
        event.preventDefault();

        const newName = nameInput.value.trim();
        const newEmail = emailInput.value.trim().toLowerCase();

        if (!newName || !newEmail) {
            message.textContent = "يرجى إدخال الاسم والبريد الإلكتروني.";
            return;
        }

        const oldEmail = sessionStorage.getItem("pg_user_email");

        let currentAccount;

        try {
            currentAccount = JSON.parse(
                localStorage.getItem("pg_account_" + oldEmail)
            );
        } catch (error) {
            currentAccount = null;
        }

        if (!currentAccount) {
            message.textContent = "تعذر العثور على الحساب.";
            return;
        }

        // إذا تغيّر البريد، تأكد أنه غير مستخدم
        if (
            newEmail !== oldEmail &&
            localStorage.getItem("pg_account_" + newEmail)
        ) {
            message.textContent = "هذا البريد مستخدم في حساب آخر.";
            return;
        }

        currentAccount.name = newName;

        localStorage.setItem(
            "pg_account_" + newEmail,
            JSON.stringify(currentAccount)
        );

        if (newEmail !== oldEmail) {
            localStorage.removeItem("pg_account_" + oldEmail);
        }

        sessionStorage.setItem("pg_user_email", newEmail);
        sessionStorage.setItem("pg_user_name", newName);

        emailInput.value = newEmail;
        heading.textContent = newName;
        message.textContent = "تم حفظ التعديلات بنجاح.";
    });
});
