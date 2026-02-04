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
            if (bd.port_detected) addItem("Suspicious Port", bd.port_detected.detected, bd.port_detected.score);
        }

        if (list.children.length === 0) {
            list.innerHTML = '<li>No specific fake indicators found.</li>';
        }
    }

    resultContainer.classList.remove('hidden');
}

// Allow Enter key to submit
document.getElementById('urlInput')?.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        checkUrl();
    }
});

// --- Scam Call Detection Logic ---

function checkPhoneNumber() {
    const phoneInput = document.getElementById('phoneInput');
    const phone = phoneInput.value.trim();
    const resultContainer = document.getElementById('resultContainer');
    const loader = document.getElementById('loader');
    const checkBtn = document.getElementById('checkPhoneBtn');
    const errorMsg = document.getElementById('errorMsg');

    // Reset
    resultContainer.classList.add('hidden');
    errorMsg.textContent = '';

    if (!phone) {
        errorMsg.textContent = "Please enter a valid phone number.";
        return;
    }

    loader.classList.remove('hidden');
    checkBtn.disabled = true;
    checkBtn.textContent = "Checking...";

    fetch('/predict-call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: phone })
    })
        .then(response => response.json())
        .then(data => {
            loader.classList.add('hidden');
            checkBtn.disabled = false;
            checkBtn.textContent = "Check Number";
            displayCallResult(data);
        })
        .catch(error => {
            console.error('Error:', error);
            loader.classList.add('hidden');
            checkBtn.disabled = false;
            checkBtn.textContent = "Check Number";
            errorMsg.textContent = "An error occurred. Please try again.";
        });
}

function displayCallResult(data) {
    const resultContainer = document.getElementById('resultContainer');
    const resultStatus = document.getElementById('resultStatus');
    const resultIcon = document.getElementById('resultIcon');
    const riskLevel = document.getElementById('riskLevel');
    const confidenceValue = document.getElementById('confidenceValue');
    const reasonsList = document.getElementById('reasonsList');

    resultIcon.className = 'result-icon fas';

    // Reset specific classes
    resultStatus.className = '';
    riskLevel.className = '';

    let iconClass = '';
    let colorClass = '';

    if (data.status === 'Safe') {
        iconClass = 'fa-shield-check';
        colorClass = 'safe';
        resultStatus.textContent = "Safe Call";
    } else if (data.status === 'Suspicious') {
        iconClass = 'fa-exclamation-triangle';
        colorClass = 'suspicious';
        resultStatus.textContent = "Suspicious Call";
    } else {
        iconClass = 'fa-ban';
        colorClass = 'scam';
        resultStatus.textContent = "Potential Scam";
    }

    resultIcon.classList.add(iconClass, colorClass);
    resultStatus.classList.add(colorClass);

    riskLevel.textContent = data.risk;
    riskLevel.classList.add(colorClass);

    confidenceValue.textContent = `(${data.confidence}% Confidence)`;

    reasonsList.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(r => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fas fa-info-circle"></i> ${r}`;
            reasonsList.appendChild(li);
        });
    } else {
        reasonsList.innerHTML = '<li>No specific risk indicators found.</li>';
    }

    resultContainer.classList.remove('hidden');
}

// Allow Enter key for phone
document.getElementById('phoneInput')?.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        checkPhoneNumber();
    }
});

// --- Live Call Monitor Logic ---

let recognition;
let isMonitoring = false;
let scamKeywords = [];
let detectedSet = new Set();

// Load config on startup
fetch('/get-scam-config')
    .then(res => res.json())
    .then(data => {
        if (data.scam_keywords) {
            scamKeywords = data.scam_keywords.map(k => k.toLowerCase());
        }
    })
    .catch(err => console.error("Failed to load scam config", err));

function toggleLiveMonitor() {
    const btn = document.getElementById('startMonitorBtn');
    const indicator = document.getElementById('recordingIndicator');

    if (isMonitoring) {
        stopMonitoring();
        btn.innerHTML = '<i class="fas fa-play"></i> Start Listening';
        btn.style.backgroundColor = '#2ecc71';
        indicator.classList.add('hidden');
    } else {
        startMonitoring();
        btn.innerHTML = '<i class="fas fa-stop"></i> Stop Listening';
        btn.style.backgroundColor = '#e74c3c';
        indicator.classList.remove('hidden');
    }
}

function startMonitoring() {
    if (!('webkitSpeechRecognition' in window)) {
        alert("Web Speech API is not supported in this browser. Please use Chrome/Edge.");
        return;
    }

    recognition = new webkitSpeechRecognition();
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = 'en-US';

    recognition.onstart = function () {
        isMonitoring = true;
        detectedSet.clear();
        updateRiskUI();
        document.getElementById('transcriptBox').innerHTML = '<span style="color: #888;">Listening...</span>';
    };

    recognition.onerror = function (event) {
        console.error("Speech recognition error", event.error);
        if (event.error === 'not-allowed') {
            alert("Microphone access denied.");
            stopMonitoring();
        }
    };

    recognition.onend = function () {
        if (isMonitoring) {
            recognition.start(); // Auto-restart if stopped unexpectedly
        }
    };

    recognition.onresult = function (event) {
        let interimTranscript = '';
        let finalTranscript = '';

        for (let i = event.resultIndex; i < event.results.length; ++i) {
            if (event.results[i].isFinal) {
                finalTranscript += event.results[i][0].transcript;
                processText(event.results[i][0].transcript);
            } else {
                interimTranscript += event.results[i][0].transcript;
            }
        }

        // Show in UI
        const box = document.getElementById('transcriptBox');
        // Only keep last few lines to avoid overflow issues visually
        box.innerHTML = `<div style="color: #333;">${finalTranscript} <span style="color: #999;">${interimTranscript}</span></div>`;
        box.scrollTop = box.scrollHeight;
    };

    recognition.start();
}

function stopMonitoring() {
    isMonitoring = false;
    if (recognition) {
        recognition.stop();
    }
}

function processText(text) {
    const lowerText = text.toLowerCase();

    scamKeywords.forEach(keyword => {
        if (lowerText.includes(keyword)) {
            if (!detectedSet.has(keyword)) {
                detectedSet.add(keyword);
                addKeywordBadge(keyword);
                updateRiskUI();
            }
        }
    });
}

function addKeywordBadge(keyword) {
    const container = document.getElementById('detectedKeywords');
    const badge = document.createElement('span');
    badge.textContent = keyword;
    badge.style.cssText = `
        background-color: #e74c3c; 
        color: white; 
        padding: 5px 10px; 
        border-radius: 15px; 
        font-size: 0.8rem;
        display: inline-block;
        animation: fadeIn 0.3s;
    `;
    container.appendChild(badge);
}

function updateRiskUI() {
    const scoreEl = document.getElementById('liveRiskScore');
    const count = detectedSet.size;

    // Simple logic: more words = higher risk
    let risk = Math.min(count * 20, 100);

    scoreEl.textContent = risk + "%";

    if (risk < 30) scoreEl.style.color = '#2ecc71';
    else if (risk < 70) scoreEl.style.color = '#f1c40f';
    else scoreEl.style.color = '#e74c3c';

    if (risk > 50) {
        // Flash warning or sound could go here
    }
}
