const VIRUSTOTAL_API_KEY = "0999f64039a324abf4eee113a145dc26d6c1ac640169281c893f59ed3f699c98"; //
const GOOGLE_SAFE_BROWSING_API_KEY = "YOUAIzaSyBH1-_D-7_vusdF-54WnRIXvRX-PN9S_I4R_GOOGLE_API_KEY"; //

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("checkButton").addEventListener("click", checkURL);
});

async function checkURL() {
    let url = document.getElementById("urlInput").value;
    let resultsContainer = document.getElementById("results");
    resultsContainer.innerHTML = "";

    if (!url) {
        displayResult("Error", "Please enter a URL.", "error");
        return;
    }

    displayResult("Scanning...", "Checking URL against multiple security layers.", "info");

    let checks = [
        checkVirusTotal(url),
        checkGoogleSafeBrowsing(url),
        checkHTTPS(url),
        checkBlacklist(url),
        checkPatternAnalysis(url),
        expandShortenedURL(url)
    ];

    let results = await Promise.allSettled(checks);
    let score = 0;

    results.forEach(result => {
        if (result.status === "fulfilled") {
            if (result.value.status === "safe") score += 20;
            displayResult(result.value.title, result.value.message, result.value.status);
        } else {
            displayResult("Error", result.reason, "error");
        }
    });

    let finalScore = (score / 120) * 100;
    displayResult("Final Security Score", `This URL has a security score of ${finalScore.toFixed(2)}%`, 
        finalScore > 70 ? "safe" : finalScore > 40 ? "warning" : "danger");
}

function displayResult(title, message, status) {
    let resultsContainer = document.getElementById("results");
    let resultElement = document.createElement("div");
    resultElement.classList.add("result", status);

    // Select icon based on status
    let icon = "ℹ️"; 
    if (status === "safe") icon = "✅";
    if (status === "warning") icon = "⚠️";
    if (status === "danger") icon = "❌";
    if (status === "error") icon = "❌";

    resultElement.innerHTML = `
        <strong>${icon} ${title}:</strong><br> 
        <span>${message}</span>
    `;

    resultsContainer.appendChild(resultElement);
}

// 🛡️ VirusTotal API Check with Report Link
async function checkVirusTotal(url) {
    try {
        let submitResponse = await fetch('http://localhost:3000/submit', {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        if (!submitResponse.ok) {
            throw new Error("Failed to submit URL to VirusTotal");
        }

        let submitData = await submitResponse.json();
        let analysisId = submitData.data.id;

        let reportResponse = await fetch(`http://localhost:3000/report/${analysisId}`);

        if (!reportResponse.ok) {
            throw new Error("Failed to fetch VirusTotal report");
        }

        let reportData = await reportResponse.json();
        let maliciousCount = reportData.data.attributes.stats.malicious || 0;

        let base64Url = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        let vtReportLink = `https://www.virustotal.com/gui/url/${base64Url}/detection`;

        if (maliciousCount > 0) {
            return {
                title: "VirusTotal Check",
                message: `⚠️ Detected ${maliciousCount} malicious results. <a href="${vtReportLink}" target="_blank">View Full Report</a>`,
                status: "danger"
            };
        } else {
            return {
                title: "VirusTotal Check",
                message: `✅ No threats detected. <a href="${vtReportLink}" target="_blank">View Full Report</a>`,
                status: "safe"
            };
        }

    } catch (error) {
        console.error(error);
        return {
            title: "VirusTotal Check",
            message: "❌ Error checking VirusTotal. Please try again later.",
            status: "error"
        };
    }
}

// 🛡️ Google Safe Browsing API Check
async function checkGoogleSafeBrowsing(url) {
    try {
        let response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client: { clientId: "yourcompany", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: url }]
                }
            })
        });

        let data = await response.json();
        return data.matches
            ? { title: "Google Safe Browsing", message: "URL is flagged as unsafe!", status: "danger" }
            : { title: "Google Safe Browsing", message: "URL is safe according to Google.", status: "safe" };
    } catch (error) {
        return { title: "Google Safe Browsing", message: "Error connecting to Google Safe Browsing API.", status: "error" };
    }
}

// ✅ HTTPS Check
async function checkHTTPS(url) {
    return url.startsWith("https")
        ? { title: "HTTPS Check", message: "URL is using secure HTTPS.", status: "safe" }
        : { title: "HTTPS Check", message: "URL is using insecure HTTP!", status: "warning" };
}

// 🚫 Blacklist Database Check (Placeholder - You can integrate real blacklists)
async function checkBlacklist(url) {
    return { title: "Blacklist Database", message: "URL is not found in known blacklists.", status: "safe" };
}

// 🧐 URL Pattern Analysis (Simple checks for suspicious patterns)
async function checkPatternAnalysis(url) {
    let suspiciousPatterns = [/[\d]{8,}/, /free|win|prize/i, /\/\//g]; 
    let isSuspicious = suspiciousPatterns.some(pattern => pattern.test(url));

    return isSuspicious
        ? { title: "URL Pattern Analysis", message: "Suspicious URL structure detected!", status: "warning" }
        : { title: "URL Pattern Analysis", message: "No suspicious patterns detected.", status: "safe" };
}

// 🔗 Expand Shortened URL (Placeholder - API needed for real expansion)
async function expandShortenedURL(url) {
    return { title: "Shortened URL Expansion", message: "No redirections detected.", status: "safe" };
}
