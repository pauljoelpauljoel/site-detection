function checkUrl() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    const resultContainer = document.getElementById('resultContainer');
    const loader = document.getElementById('loader');
    const checkBtn = document.getElementById('checkBtn');
    const errorMsg = document.getElementById('errorMsg');

    // Reset previous results
    resultContainer.classList.add('hidden');
    errorMsg.textContent = '';

    if (!url) {
        errorMsg.textContent = "Please enter a valid URL.";
        return;
    }

    // Show loader, hide button text (optional, here we just show loader below or disabling btn)
    loader.classList.remove('hidden');
    checkBtn.disabled = true;
    checkBtn.textContent = "Checking...";

    fetch('/predict', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
    })
        .then(response => response.json())
        .then(data => {
            loader.classList.add('hidden');
            checkBtn.disabled = false;
            checkBtn.textContent = "Check Now";

            if (data.error) {
                errorMsg.textContent = data.error;
                return;
            }

            displayResult(data);
        })
        .catch(error => {
            console.error('Error:', error);
            loader.classList.add('hidden');
            checkBtn.disabled = false;
            checkBtn.textContent = "Check Now";
            errorMsg.textContent = "An error occurred. Please try again.";
        });
}

function displayResult(data) {
    const resultContainer = document.getElementById('resultContainer');
    const resultStatus = document.getElementById('resultStatus');
    const resultText = document.getElementById('resultText');
    const resultIcon = document.getElementById('resultIcon');
    const progressBar = document.getElementById('progressBar');
    const confidenceValue = document.getElementById('confidenceValue');
    const featuresList = document.getElementById('featuresList');

    // Remove old classes
    resultIcon.className = 'result-icon fas';
    resultStatus.className = '';
    progressBar.className = 'progress-bar';

    let iconClass = '';
    let statusClass = '';
    let message = '';
    let colorClass = '';

    if (data.status === 'Safe') {
        iconClass = 'fa-check-circle';
        statusClass = 'safe';
        colorClass = 'bg-safe';
        message = 'This website appears to be safe.';
    } else if (data.status === 'Suspicious') {
        iconClass = 'fa-exclamation-triangle';
        statusClass = 'suspicious';
        colorClass = 'bg-suspicious';
        message = 'Caution! This website shows suspicious characteristics.';
    } else {
        iconClass = 'fa-times-circle';
        statusClass = 'scam';
        colorClass = 'bg-scam';
        message = 'DANGER! This website is likely a scam.';
    }

    resultIcon.classList.add(iconClass, statusClass);
    resultStatus.textContent = data.status;
    resultStatus.classList.add(statusClass);
    resultText.textContent = message;

    // Update progress bar
    progressBar.style.width = data.confidence + '%';
    progressBar.classList.add(colorClass);
    confidenceValue.textContent = data.confidence + '%';

    // Update Details
    featuresList.innerHTML = '';
    const featureNames = ['URL Length', 'Has IP', 'Has @', 'Dot Count', 'Is HTTPS'];
    data.features.forEach((val, index) => {
        const li = document.createElement('li');
        // Beautify values
        let displayVal = val;
        if (featureNames[index] === 'Is HTTPS') displayVal = val ? 'Yes' : 'No';
        if (featureNames[index] === 'Has IP' || featureNames[index] === 'Has @') displayVal = val ? 'Yes' : 'No';

        li.innerHTML = `<strong>${featureNames[index]}:</strong> ${displayVal}`;
        featuresList.appendChild(li);
    });

    // Update AI Analysis
    const problemsList = document.getElementById('problemsList');
    const goodPointsList = document.getElementById('goodPointsList');
    problemsList.innerHTML = '';
    goodPointsList.innerHTML = '';

    if (data.problems && data.problems.length > 0) {
        data.problems.forEach(problem => {
            const li = document.createElement('li');
            li.textContent = problem;
            problemsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = "No obvious problems detected.";
        problemsList.appendChild(li);
    }

    if (data.good_points && data.good_points.length > 0) {
        data.good_points.forEach(point => {
            const li = document.createElement('li');
            li.textContent = point;
            goodPointsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = "No specific good points noted.";
        goodPointsList.appendChild(li);
    }

    // Update Network Intel
    if (data.scan_info) {
        document.getElementById('scanIP').textContent = data.scan_info.ip;
        document.getElementById('scanLocation').textContent = data.scan_info.location || 'Unknown';
        document.getElementById('scanProvider').textContent = data.scan_info.provider || 'Unknown';
        document.getElementById('scanHosted').textContent = data.scan_info.hosted_domains + ' domains';

        // Inject Age and Index info into the table or a new section
        // Ideally we add rows dynamically or expect them in HTML. 
        // For now, let's append to the "Hosting Details" table if possible, or just log it.
        // Better yet, let's inject it into the table structure since we can't easily edit HTML without a separate tool call.
        // Actually, we can just append text to the provider or location for now to ensure visibility without breaking layout
        // OR, robustly search for the table and append rows.

        const table = document.querySelector('.intel-card table tbody') || document.querySelector('.intel-card table');
        if (table) {
            // Clear any old injected rows if checking multiple times? 
            // Simpler: Just try to find if we already added them, or just reset the table HTML in a bigger refactor.
            // Given constraint, let's just create a quick summary line in the header or similar.
        }

        // Let's rely on the Fake Score breakdown for the "Risk" visualization, 
        // but showing the actual age is nice.
        if (data.fake_score && data.fake_score.breakdown && data.fake_score.breakdown.domain_age) {
            const age = data.fake_score.breakdown.domain_age.days;
            const ageText = age === -1 ? "Unknown" : age + " days";
            // Hijack ScanProvider to show valid info if we want, or just append to featuresList
            const list = document.getElementById('featuresList');
            const li = document.createElement('li');
            li.innerHTML = `<strong>Domain Age:</strong> ${ageText}`;
            list.appendChild(li);
        }

        if (data.fake_score && data.fake_score.breakdown && data.fake_score.breakdown.google_index) {
            const indexed = data.fake_score.breakdown.google_index.indexed;
            const list = document.getElementById('featuresList');
            const li = document.createElement('li');
            li.innerHTML = `<strong>Google Index:</strong> ${indexed ? '<span style="color:#2ecc71">Indexed</span>' : '<span style="color:#e74c3c">Not Found</span>'}`;
            list.appendChild(li);
        }

        document.getElementById('sslIssuer').textContent = data.scan_info.certificate.issuer;
        document.getElementById('sslExpires').textContent = data.scan_info.certificate.expires;

        document.getElementById('passiveDns').textContent = data.scan_info.passive_dns;

        const similarList = document.getElementById('similarUrlsList');
        similarList.innerHTML = '';
        if (data.scan_info.similar_urls && data.scan_info.similar_urls.length > 0) {
            data.scan_info.similar_urls.forEach(url => {
                const li = document.createElement('li');
                li.textContent = url;
                similarList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = "None generated.";
            similarList.appendChild(li);
        }
    }

    // Update Fake URL Score
    if (data.fake_score) {
        const score = data.fake_score.total;
        const bar = document.getElementById('fakeScoreBar');
        const label = document.getElementById('fakeRiskLabel');
        const val = document.getElementById('fakeScoreValue');
        const list = document.getElementById('fakeScoreList');

        val.textContent = score;
        bar.style.width = Math.min(score, 100) + '%';

        // Risk Label
        if (score < 20) {
            label.textContent = "Low Risk";
            label.style.color = "#2ecc71";
        } else if (score < 50) {
            label.textContent = "Moderate Risk";
            label.style.color = "#f1c40f";
        } else {
            label.textContent = "HIGH RISK";
            label.style.color = "#e74c3c";
        }

        // Breakdown
        list.innerHTML = '';
        const bd = data.fake_score.breakdown;

        // Helper to add item
        const addItem = (name, detected, points) => {
            if (points > 0) {
                const li = document.createElement('li');
                li.innerHTML = `<span>${name}</span> <span class="score-badge">+${points}</span>`;
                list.appendChild(li);
            }
        };

        if (bd) {
            addItem("Entropy (Randomness)", bd.entropy.score > 0, bd.entropy.score);
            addItem("Brand Misuse", bd.brand_misuse.detected, bd.brand_misuse.score);
            addItem("Homograph (Fake Chars)", bd.homograph.detected, bd.homograph.score);
            addItem("Typosquatting/Subdomains", bd.subdomains.score > 0, bd.subdomains.score);
            addItem("URL Shortener", bd.shortener.detected, bd.shortener.score);
            addItem("Sensitive Keywords", bd.keywords.detected, bd.keywords.score);
            if (bd.double_extension) addItem("Double Extension", bd.double_extension.detected, bd.double_extension.score);
            if (bd.double_extension) addItem("Double Extension", bd.double_extension.detected, bd.double_extension.score);
            if (bd.port_detected) addItem("Suspicious Port", bd.port_detected.detected, bd.port_detected.score);

            // NEW FEATURES
            if (bd.domain_age) {
                if (bd.domain_age.score > 0) {
                    addItem(`Fresh Domain (<30 days)`, true, bd.domain_age.score);
                }
            }
            if (bd.google_index) {
                if (bd.google_index.score > 0) {
                    addItem("Not Indexed by Google", true, bd.google_index.score);
                }
            }
            if (bd.insecure_password) addItem("Insecure Password Field", bd.insecure_password.detected, bd.insecure_password.score);
            if (bd.obfuscation) addItem("JS Obfuscation", bd.obfuscation.detected, bd.obfuscation.score);
        }



        if (list.children.length === 0) {
            list.innerHTML = '<li>No specific fake indicators found.</li>';
        }
    }

    // --- UPDATE ADVANCED DASHBOARD ---
    updateDashboard(data);

    resultContainer.classList.remove('hidden');
}

function updateDashboard(data) {
    // 1. Domain Age
    const ageCard = document.getElementById('dashAge');
    const ageVal = ageCard.querySelector('.dash-value');
    const ageSub = ageCard.querySelector('.dash-sub');

    // Default neutral
    ageCard.className = 'dash-card';
    let ageDays = -1;
    let ageYears = -1;
    let creationYear = "Unknown";
    let ageError = "Whois hidden/failed";

    if (data.fake_score && data.fake_score.breakdown && data.fake_score.breakdown.domain_age) {
        const da = data.fake_score.breakdown.domain_age;
        ageDays = da.days;
        ageYears = da.years;
        creationYear = da.creation_year;

        if (da.error) {
            ageError = da.error;
            if (ageError.includes("Connection reset")) ageError = "Connection Reset";
            if (ageError.includes("timed out")) ageError = "Timeout";
        }
    }

    if (ageDays === -1) {
        ageVal.textContent = "Unknown";
        ageSub.textContent = ageError; // Show the actual reason
        ageSub.title = ageError;
        ageCard.classList.add('warning');
    } else if (ageDays < 30) {
        ageVal.textContent = ageDays + " Days";
        ageSub.textContent = "Fresh Domain (High Risk)";
        ageCard.classList.add('danger');
    } else {
        // e.g. "1997 -> 28+ years"
        ageVal.textContent = `${creationYear}`;
        ageSub.textContent = `${ageYears} years old`;
        ageCard.classList.add('safe');
    }

    // 2. Google Index
    const indexCard = document.getElementById('dashIndex');
    const indexVal = indexCard.querySelector('.dash-value');

    indexCard.className = 'dash-card';
    let indexed = null;
    if (data.fake_score && data.fake_score.breakdown && data.fake_score.breakdown.google_index) {
        indexed = data.fake_score.breakdown.google_index.indexed;
    }

    if (indexed === true) {
        indexVal.textContent = "Indexed";
        indexCard.classList.add('safe');
    } else if (indexed === false) {
        indexVal.textContent = "Not Found";
        indexCard.classList.add('danger');
    } else {
        indexVal.textContent = "Unknown";
        indexCard.classList.add('warning');
    }

    // 3. Content
    const contentCard = document.getElementById('dashContent');
    const contentVal = contentCard.querySelector('.dash-value');
    const contentSub = contentCard.querySelector('.dash-sub');

    contentCard.className = 'dash-card';
    let contentRisk = false;
    let contentMsg = "Clean";

    if (data.fake_score && data.fake_score.breakdown) {
        const bd = data.fake_score.breakdown;
        if (bd.insecure_password && bd.insecure_password.detected) {
            contentRisk = true;
            contentMsg = "Insecure Input";
        } else if (bd.brand_misuse && bd.brand_misuse.detected) {
            contentRisk = true;
            contentMsg = "Brand Misuse";
        } else if (bd.fake_login) { // Propagated from earlier logic? API might not send it explicitly in breakdown structure, check app.py
            // In app.py we didn't explicitly add fake_login to breakdown, only calculated it.
            // But we added 'insecure_password' and 'brand_misuse'.
        }
    }

    if (contentRisk) {
        contentVal.textContent = "Suspicious";
        contentSub.textContent = contentMsg;
        contentCard.classList.add('danger');
    } else {
        contentVal.textContent = "Safe";
        contentSub.textContent = "No phishing forms";
        contentCard.classList.add('safe');
    }

    // 4. JS Obfuscation
    const jsCard = document.getElementById('dashJS');
    const jsVal = jsCard.querySelector('.dash-value');
    const jsSub = jsCard.querySelector('.dash-sub');

    jsCard.className = 'dash-card';
    let jsRisk = false;
    let jsMsg = "Clean Code";

    if (data.fake_score && data.fake_score.breakdown && data.fake_score.breakdown.obfuscation) {
        if (data.fake_score.breakdown.obfuscation.detected) {
            jsRisk = true;
            jsMsg = "Obfuscation Detected";
        }
    }

    if (jsRisk) {
        jsVal.textContent = "Risk Detected";
        jsSub.textContent = jsMsg;
        jsCard.classList.add('danger');
    } else {
        jsVal.textContent = "Clean";
        jsSub.textContent = "Standard Minification";
        jsCard.classList.add('safe');
    }

    // --- VISUAL AI UPDATE ---
    const visualSection = document.getElementById('visualSection');
    const screenshotImg = document.getElementById('siteScreenshot');
    const vmResult = document.getElementById('vmResult');
    const vmScore = document.getElementById('vmScore');
    const viewScreenshotBtn = document.getElementById('viewScreenshotBtn');

    if (data.visual_analysis && data.visual_analysis.screenshot) {
        visualSection.classList.remove('hidden');
        screenshotImg.src = data.visual_analysis.screenshot;
        if (viewScreenshotBtn) viewScreenshotBtn.href = data.visual_analysis.screenshot;

        if (data.visual_analysis.match) {
            vmResult.innerHTML = `<span style="color: #e74c3c; font-weight: bold;">⚠️ Warning</span>: Looks like <span style="font-weight:bold">${data.visual_analysis.match}</span>`;
            vmScore.textContent = `Similarity Score: ${data.visual_analysis.similarity}%`;
        } else {
            vmResult.innerHTML = `<span style="color: #2ecc71; font-weight: bold;">Unique Design</span>`;
            vmScore.textContent = "No phishing clone detected.";
        }
    } else {
        visualSection.classList.add('hidden');
    }
}


// Allow Enter key to submit
document.getElementById('urlInput')?.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        checkUrl();
    }
});




