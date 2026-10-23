"use strict";

// ======================================
// PHISHGUARD - EMAIL RISK ANALYZER
// Rule-based detection engine
// ======================================


const form = document.getElementById("analyzerForm");

const subjectInput = document.getElementById("emailSubject");
const emailInput = document.getElementById("emailContent");

const charCount = document.getElementById("charCount");

const resultsSection = document.getElementById("results");

const riskScoreElement = document.getElementById("riskScore");
const riskTitleElement = document.getElementById("riskTitle");
const riskDescriptionElement =
    document.getElementById("riskDescription");

const resultBadge = document.getElementById("resultBadge");

const scoreRing = document.getElementById("scoreRing");
const scoreProgress = document.getElementById("scoreProgress");

const indicatorList = document.getElementById("indicatorList");
const indicatorCount = document.getElementById("indicatorCount");

const recommendationText =
    document.getElementById("recommendationText");

const historyList = document.getElementById("historyList");

const analysisCount = document.getElementById("analysisCount");

const sampleBtn = document.getElementById("sampleBtn");
const clearBtn = document.getElementById("clearBtn");

const clearHistoryBtn =
    document.getElementById("clearHistoryBtn");


// ======================================
// DETECTION RULES
// ======================================

// These are heuristic rules, not a trained AI model.
// Weights are illustrative and should be tested and refined.

const rules = [

    {
        id: "credential",
        title: "Sensitive Information Request",
        description:
            "The message may ask for a password, verification code, or other sensitive information.",
        weight: 30,

        patterns: [
            /\benter your password\b/i,
            /\bprovide your password\b/i,
            /\bconfirm your password\b/i,
            /\bshare your password\b/i,
            /\bsend us your password\b/i,
            /\benter your otp\b/i,
            /\bshare your otp\b/i,
            /\bverification code\b/i,
            /\bcredit card details\b/i,
            /\bbank account details\b/i
        ]
    },

    {
        id: "urgency",
        title: "Urgent or Threatening Language",
        description:
            "The message may pressure you to act quickly or threaten a negative consequence.",
        weight: 15,

        patterns: [
            /\bact immediately\b/i,
            /\bimmediately\b/i,
            /\bwithin 24 hours\b/i,
            /\baccount will be blocked\b/i,
            /\baccount will be suspended\b/i,
            /\bfinal warning\b/i,
            /\bact now\b/i,
            /\burgent action required\b/i,
            /\bverify immediately\b/i
        ]
    },

    {
        id: "prize",
        title: "Unexpected Prize or Reward",
        description:
            "The message may claim that you won an unexpected prize or reward.",
        weight: 20,

        patterns: [
            /\byou have won\b/i,
            /\byou won\b/i,
            /\bclaim your prize\b/i,
            /\blottery winner\b/i,
            /\bcongratulations.{0,60}\bwon\b/i,
            /\bclaim your reward\b/i,
            /\bfree gift\b/i
        ]
    },

    {
        id: "money",
        title: "Suspicious Money Request",
        description:
            "The message may ask for money or promise an unusually large financial reward.",
        weight: 20,

        patterns: [
            /\bpay a small fee\b/i,
            /\bprocessing fee\b/i,
            /\btransfer money\b/i,
            /\bwire transfer\b/i,
            /\bclaim your inheritance\b/i,
            /\bguaranteed profit\b/i,
            /\bdouble your money\b/i
        ]
    },

    {
        id: "account",
        title: "Account Verification Request",
        description:
            "The message may ask you to verify or restore access to an account.",
        weight: 15,

        patterns: [
            /\bverify your account\b/i,
            /\bconfirm your account\b/i,
            /\brestore your account\b/i,
            /\baccount verification required\b/i,
            /\bvalidate your account\b/i
        ]
    },

    {
        id: "link",
        title: "Potentially Risky Link",
        description:
            "A link may use a URL shortener, an unusual format, or a domain written as an IP address.",
        weight: 15,

        patterns: []
    },

    {
        id: "impersonation",
        title: "Possible Impersonation Language",
        description:
            "The message may claim to come from a trusted organization or authority.",
        weight: 10,

        patterns: [
            /\bwe are from your bank\b/i,
            /\bgovernment refund\b/i,
            /\bsecurity team requires\b/i,
            /\bverify your identity now\b/i
        ]
    }

];


// ======================================
// HELPER FUNCTIONS
// ======================================

function getMatches(text, patterns) {

    const matches = [];

    for (const pattern of patterns) {

        if (pattern.test(text)) {
            matches.push(pattern.source);
        }

    }

    return matches;
}


function findURLs(text) {

    const pattern = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;

    return text.match(pattern) || [];
}


function getURLWarning(url) {

    const warnings = [];

    let parsedURL;

    try {

        const normalizedURL = /^https?:\/\//i.test(url)
            ? url
            : "https://" + url;

        parsedURL = new URL(normalizedURL);

    } catch (error) {

        return {
            suspicious: true,
            reason: "The link could not be parsed reliably."
        };

    }

    const hostname = parsedURL.hostname.toLowerCase();

    // URL shorteners can conceal the destination.
    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy"
    ];

    if (shorteners.includes(hostname)) {

        warnings.push(
            "The URL uses a link-shortening service."
        );

    }

    // An IP address used as a hostname deserves inspection.
    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {

        warnings.push(
            "The link uses an IP address instead of a typical domain name."
        );

    }

    // Unicode domain names can sometimes resemble other domains.
    if (hostname.startsWith("xn--") ||
        hostname.includes(".xn--")) {

        warnings.push(
            "The domain uses internationalized encoding and deserves closer inspection."
        );

    }

    // HTTPS alone does not prove that a site is trustworthy.
    if (parsedURL.protocol !== "https:") {

        warnings.push(
            "The link does not use HTTPS."
        );

    }

    return {
        suspicious: warnings.length > 0,
        reason: warnings.join(" ")
    };

}


// ======================================
// EMAIL ANALYSIS
// ======================================

function analyzeEmail(subject, email) {

    const fullText = (subject + "\n" + email).trim();

    const findings = [];

    let score = 0;


    // Check text-based rules.

    for (const rule of rules) {

        if (rule.id === "link") {
            continue;
        }

        const matches = getMatches(
            fullText,
            rule.patterns
        );

        if (matches.length > 0) {

            findings.push({
                id: rule.id,
                title: rule.title,
                description: rule.description,
                points: rule.weight
            });

            score += rule.weight;

        }

    }


    // Check URLs separately.

    const urls = findURLs(fullText);

    const urlWarnings = [];

    for (const url of urls) {

        const warning = getURLWarning(url);

        if (warning.suspicious) {

            urlWarnings.push({
                url: url,
                reason: warning.reason
            });

        }

    }


    // Count URL findings as one category.
    // Multiple suspicious URLs do not repeatedly add the same points.

    if (urlWarnings.length > 0) {

        findings.push({
            id: "link",
            title: "Potentially Risky Link",
            description: urlWarnings
                .map(item => item.reason)
                .join(" "),
            points: rules.find(rule => rule.id === "link").weight
        });

        score += rules.find(
            rule => rule.id === "link"
        ).weight;

    }


    // Avoid claiming that absence of warning signs proves safety.

    score = Math.min(score, 100);


    let level;
    let title;
    let description;
    let recommendation;
    let color;


    if (score >= 50) {

        level = "HIGH";
        title = "High Risk Indicators";
        description =
            "Several warning signs were found. Treat this message cautiously.";

        recommendation =
            "Do not click suspicious links or provide sensitive information. Verify the sender using an independently obtained official contact method.";

        color = "#fb7185";

    } else if (score >= 20) {

        level = "MEDIUM";
        title = "Some Warning Signs";
        description =
            "Potentially suspicious characteristics were found. Review the message carefully.";

        recommendation =
            "Check the sender's full address and verify unusual requests through an independent, trusted channel before taking action.";

        color = "#fbbf24";

    } else {

        level = "LOW";
        title = "Few Warning Signs Detected";
        description =
            "Few indicators matched our rules. This does not mean the email is safe.";

        recommendation =
            "Remain cautious. Check the sender and destination of any link independently, especially before sharing information or making payments.";

        color = "#34d399";

    }


    return {
        score,
        level,
        title,
        description,
        recommendation,
        color,
        findings,
        urlsChecked: urls.length
    };

}


// ======================================
// DISPLAY RESULTS
// ======================================

function renderResults(result) {

    resultsSection.hidden = false;

    riskScoreElement.textContent = result.score;

    riskTitleElement.textContent = result.title;

    riskDescriptionElement.textContent =
        result.description;

    recommendationText.textContent =
        result.recommendation;

    resultBadge.textContent = result.level + " RISK";

    resultBadge.style.color = result.color;

    resultBadge.style.background =
        result.color + "20";


    scoreRing.style.background =
        `conic-gradient(
            ${result.color} ${result.score * 3.6}deg,
            #263148 ${result.score * 3.6}deg
        )`;

    scoreProgress.style.width = result.score + "%";

    scoreProgress.style.background = result.color;


    indicatorList.replaceChildren();

    indicatorCount.textContent =
        result.findings.length + " found";


    if (result.findings.length === 0) {

        const emptyMessage = document.createElement("div");

        emptyMessage.className = "no-indicators";

        emptyMessage.textContent =
            "No configured warning patterns were detected. This does not establish that the email is legitimate.";

        indicatorList.appendChild(emptyMessage);

    } else {

        for (const finding of result.findings) {

            const item = document.createElement("article");

            item.className = "indicator-item";


            const icon = document.createElement("div");

            icon.className = "indicator-icon";
            icon.textContent = "⚠";


            const content = document.createElement("div");


            const heading = document.createElement("h5");

            heading.textContent = finding.title;


            const description = document.createElement("p");

            description.textContent = finding.description;


            content.appendChild(heading);
            content.appendChild(description);

            item.appendChild(icon);
            item.appendChild(content);

            indicatorList.appendChild(item);

        }

    }


    // Move focus to the results for accessibility.

    resultsSection.setAttribute("tabindex", "-1");

    resultsSection.focus({
        preventScroll: true
    });

    resultsSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}


// ======================================
// ANALYSIS HISTORY
// ======================================

let history = [];
let totalAnalyses = 0;


function addHistory(subject, result) {

    totalAnalyses++;

    analysisCount.textContent = totalAnalyses;


    const entry = {
        subject: subject.trim() || "Untitled email",
        score: result.score,
        level: result.level,
        color: result.color,
        time: new Date().toLocaleTimeString()
    };


    history.unshift(entry);

    // Keep only the latest 10 entries.

    history = history.slice(0, 10);

    renderHistory();

}


function renderHistory() {

    historyList.replaceChildren();

    if (history.length === 0) {

        const empty = document.createElement("div");

        empty.className = "empty-history";


        const icon = document.createElement("span");
        icon.textContent = "◷";


        const title = document.createElement("p");
        title.textContent = "No analysis yet.";


        const message = document.createElement("small");

        message.textContent =
            "Your recent analyses will appear here.";


        empty.appendChild(icon);
        empty.appendChild(title);
        empty.appendChild(message);

        historyList.appendChild(empty);

        return;

    }


    for (const entry of history) {

        const item = document.createElement("article");

        item.className = "history-item";


        const dot = document.createElement("span");

        dot.className = "history-indicator";
        dot.style.background = entry.color;


        const main = document.createElement("div");

        main.className = "history-main";


        const title = document.createElement("h4");

        title.textContent = entry.subject;


        const meta = document.createElement("p");

        meta.textContent =
            `${entry.level} RISK · ${entry.time}`;


        const score = document.createElement("span");

        score.className = "history-score";

        score.style.color = entry.color;

        score.textContent = entry.score + "/100";


        main.appendChild(title);
        main.appendChild(meta);

        item.appendChild(dot);
        item.appendChild(main);
        item.appendChild(score);

        historyList.appendChild(item);

    }

}


// ======================================
// FORM EVENTS
// ======================================

form.addEventListener("submit", function(event) {

    event.preventDefault();

    const subject = subjectInput.value.trim();

    const email = emailInput.value.trim();


    if (!email) {

        emailInput.focus();

        emailInput.setCustomValidity(
            "Please enter the email content first."
        );

        emailInput.reportValidity();

        return;

    }


    emailInput.setCustomValidity("");


    const result = analyzeEmail(subject, email);

    renderResults(result);

    addHistory(subject, result);

});


// Clear custom validation message when typing.

emailInput.addEventListener("input", function() {

    emailInput.setCustomValidity("");

    charCount.textContent =
        emailInput.value.length + " characters";

});


// ======================================
// SAMPLE EMAIL
// ======================================

sampleBtn.addEventListener("click", function() {

    subjectInput.value =
        "Urgent: Claim Your Prize";

    emailInput.value =
        "Congratulations! You have won $10,000. " +
        "Act immediately to claim your prize. " +
        "Verify your account and enter your password " +
        "to receive your reward. Visit http://bit.ly/example";

    charCount.textContent =
        emailInput.value.length + " characters";

    emailInput.setCustomValidity("");

    emailInput.focus();

});


// ======================================
// CLEAR FORM
// ======================================

clearBtn.addEventListener("click", function() {

    subjectInput.value = "";

    emailInput.value = "";

    charCount.textContent = "0 characters";

    emailInput.setCustomValidity("");

    resultsSection.hidden = true;

    subjectInput.focus();

});


// ======================================
// CLEAR HISTORY
// ======================================

clearHistoryBtn.addEventListener("click", function() {

    history = [];

    renderHistory();

});


// ======================================
// INITIALIZE
// ======================================

renderHistory();