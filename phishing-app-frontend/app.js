document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const urlInput = document.getElementById('urlInput');
    const loadingState = document.getElementById('loadingState');
    const loadingMessage = document.getElementById('loadingMessage');
    const resultsDashboard = document.getElementById('resultsDashboard');
    const newScanBtn = document.getElementById('newScanBtn');
    const urlHint = document.getElementById('urlHint');
    const toastContainer = document.getElementById('toastContainer');
    const historyList = document.getElementById('historyList');
    const historyEmpty = document.getElementById('historyEmpty');

    // Results Elements
    const threatBadge = document.getElementById('threatBadge');
    const threatLevelText = document.getElementById('threatLevelText');
    const threatIcon = threatBadge.querySelector('i');

    const scoreProgress = document.getElementById('scoreProgress');
    const riskScoreValue = document.getElementById('riskScoreValue');
    const reasonsGrid = document.getElementById('reasonsGrid');

    const API_URL = '/api/scan';
    const HISTORY_KEY = 'defend_scan_history';
    const HISTORY_MAX = 50;

    const LOADING_MESSAGES = [
        'Analyzing URL structure...',
        'Checking threat databases...',
        'Running heuristics...',
        'Almost there...'
    ];

    function showToast(message, type = 'error') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = type === 'error'
            ? `<i class="fa-solid fa-circle-exclamation"></i><span>${message}</span>`
            : `<i class="fa-solid fa-circle-check"></i><span>${message}</span>`;
        toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.animation = 'toastOut 0.25s ease forwards';
            setTimeout(() => toast.remove(), 280);
        }, 4500);
    }

    function setInputError(show) {
        urlInput.classList.toggle('input-error', show);
        urlHint.classList.toggle('error', show);
        urlHint.textContent = show ? 'Please enter a valid URL to scan.' : 'Paste a link and press Enter or click Analyze to scan.';
    }

    // --- View switching ---
    function getHistory() {
        try {
            const raw = localStorage.getItem(HISTORY_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    }

    function saveToHistory(entry) {
        const list = getHistory();
        list.unshift({
            url: entry.url,
            risk_score: entry.risk_score,
            threat_level: entry.threat_level,
            reasons: entry.reasons || [],
            at: Date.now()
        });
        const trimmed = list.slice(0, HISTORY_MAX);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
    }

    function renderHistory() {
        const list = getHistory();
        historyList.innerHTML = '';
        if (list.length === 0) {
            historyList.classList.add('hidden');
            historyEmpty.classList.remove('hidden');
            return;
        }
        historyList.classList.remove('hidden');
        historyEmpty.classList.add('hidden');
        list.forEach((item, i) => {
            const card = document.createElement('div');
            card.className = 'history-card';
            const badgeClass = item.threat_level === 'Safe' ? 'badge-safe' : item.threat_level === 'Suspicious' ? 'badge-suspicious' : 'badge-malicious';
            const date = new Date(item.at);
            const dateStr = date.toLocaleDateString(undefined, { dateStyle: 'medium' }) + ' ' + date.toLocaleTimeString(undefined, { timeStyle: 'short' });
            card.innerHTML = `
                <div class="history-card-main">
                    <span class="history-url" title="${escapeHtml(item.url)}">${escapeHtml(truncateUrl(item.url))}</span>
                    <span class="history-meta">${dateStr}</span>
                </div>
                <div class="history-card-badges">
                    <span class="threat-badge ${badgeClass}">${item.threat_level}</span>
                    <span class="history-score">${item.risk_score}% risk</span>
                </div>
                <a href="#" class="history-rescan" data-url="${escapeHtml(item.url)}" title="Scan this URL again">Rescan</a>
            `;
            historyList.appendChild(card);
        });
    }

    function truncateUrl(url, maxLen = 55) {
        if (url.length <= maxLen) return url;
        return url.slice(0, maxLen - 3) + '...';
    }

    function escapeHtml(s) {
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    }

    function switchView(viewId) {
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        const viewEl = document.getElementById('view' + viewId.charAt(0).toUpperCase() + viewId.slice(1));
        const link = document.querySelector(`.nav-link[data-view="${viewId}"]`);
        if (viewEl) viewEl.classList.add('active');
        if (link) link.classList.add('active');
        if (viewId === 'history') renderHistory();
    }

    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = link.getAttribute('data-view');
            if (view) switchView(view);
        });
    });

    document.querySelectorAll('.nav-link-trigger').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const view = btn.getAttribute('data-view');
            if (view) switchView(view);
        });
    });

    historyList.addEventListener('click', (e) => {
        const rescan = e.target.closest('.history-rescan');
        if (!rescan) return;
        e.preventDefault();
        const url = rescan.getAttribute('data-url');
        if (url) {
            switchView('scanner');
            setTimeout(() => {
                urlInput.value = url;
                urlInput.focus();
                runScan();
            }, 300);
        }
    });

    function runScan() {
        const url = urlInput.value.trim();
        if (!url) {
            setInputError(true);
            urlInput.focus();
            return;
        }
        setInputError(false);

        let finalUrl = url;
        if (!finalUrl.startsWith('http')) {
            finalUrl = 'http://' + finalUrl;
            urlInput.value = finalUrl;
        }

        resultsDashboard.classList.add('hidden');
        loadingState.classList.remove('hidden');
        scanBtn.disabled = true;

        let step = 0;
        const messageInterval = setInterval(() => {
            loadingMessage.textContent = LOADING_MESSAGES[step % LOADING_MESSAGES.length];
            step++;
        }, 800);

        fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: finalUrl })
        })
            .then(res => {
                if (!res.ok) throw new Error('Network response was not ok');
                return res.json();
            })
            .then(data => {
                clearInterval(messageInterval);
                setTimeout(() => {
                    loadingState.classList.add('hidden');
                    scanBtn.disabled = false;
                    displayResults(data.assessment);
                    saveToHistory({
                        url: data.url,
                        risk_score: data.assessment.risk_score,
                        threat_level: data.assessment.threat_level,
                        reasons: data.assessment.reasons || []
                    });
                }, 600);
            })
            .catch(err => {
                clearInterval(messageInterval);
                loadingState.classList.add('hidden');
                scanBtn.disabled = false;
                console.error('Error scanning URL:', err);
                showToast('Cannot reach the scanner. Please try again later.', 'error');
            });
    }

    scanBtn.addEventListener('click', runScan);

    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') runScan();
    });
    urlInput.addEventListener('input', () => setInputError(false));

    newScanBtn.addEventListener('click', () => {
        resultsDashboard.classList.add('hidden');
        urlInput.value = '';
        setInputError(false);
        document.querySelector('.hero')?.scrollIntoView({ behavior: 'smooth' });
        setTimeout(() => urlInput.focus(), 400);
    });

    function displayResults(assessment) {
        const { risk_score, threat_level, reasons } = assessment;

        // Reset classes
        threatBadge.className = 'threat-badge';
        threatLevelText.textContent = threat_level;

        // Set UI based on threat level
        if (threat_level === 'Safe') {
            threatBadge.classList.add('badge-safe');
            threatIcon.className = 'fa-solid fa-circle-check';
            scoreProgress.style.stroke = 'var(--safe)';
        } else if (threat_level === 'Suspicious') {
            threatBadge.classList.add('badge-suspicious');
            threatIcon.className = 'fa-solid fa-triangle-exclamation';
            scoreProgress.style.stroke = 'var(--suspicious)';
        } else {
            threatBadge.classList.add('badge-malicious');
            threatIcon.className = 'fa-solid fa-shield-virus';
            scoreProgress.style.stroke = 'var(--malicious)';
        }

        // Animate Score
        animateValue(riskScoreValue, 0, risk_score, 1000);

        // Update SVG circle path
        // Circumference is 100, so stroke-dasharray is "score, 100"
        setTimeout(() => {
            scoreProgress.setAttribute('stroke-dasharray', `${risk_score}, 100`);
        }, 100);

        // Populate Reasons Grid
        reasonsGrid.innerHTML = '';
        if (reasons.length === 0) {
            const safeCard = document.createElement('div');
            safeCard.className = 'reason-card';
            safeCard.innerHTML = `
                <i class="fa-solid fa-check reason-icon" style="color: var(--safe)"></i>
                <div>
                    <h4>No Threat Indicators</h4>
                    <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem;">The URL appears structurally sound and matches no known heuristics for phishing campaigns.</p>
                </div>
            `;
            reasonsGrid.appendChild(safeCard);
        } else {
            reasons.forEach(reason => {
                const reasonCard = document.createElement('div');
                reasonCard.className = 'reason-card';
                reasonCard.innerHTML = `
                    <i class="fa-solid fa-triangle-exclamation reason-icon" style="color: var(--malicious)"></i>
                    <div>
                        <h4>Risk Factor Detected</h4>
                        <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem;">${reason}</p>
                    </div>
                `;
                reasonsGrid.appendChild(reasonCard);
            });
        }

        // Show Dashboard
        resultsDashboard.classList.remove('hidden');
        resultsDashboard.scrollIntoView({ behavior: 'smooth' });
    }

    // Number animation helper
    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
});

