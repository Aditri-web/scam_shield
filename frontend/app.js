document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    const inputType = document.getElementById('inputType');
    const senderGroup = document.getElementById('senderGroup');
    const senderInput = document.getElementById('sender');
    const textInput = document.getElementById('text');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = scanBtn.querySelector('.btn-text');
    const spinner = scanBtn.querySelector('.spinner');
    
    // Result elements
    const resultPanel = document.getElementById('resultPanel');
    const verdictBadge = document.getElementById('verdictBadge');
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreText = document.getElementById('scoreText');
    const verdictText = document.getElementById('verdictText');
    const categoriesList = document.getElementById('categoriesList');
    const memoryStats = document.getElementById('memoryStats');
    const memoryBoost = document.getElementById('memoryBoost');
    const notificationBanner = document.getElementById('notificationBanner');
    const notifDetails = document.getElementById('notifDetails');

    // Toggle sender input based on type
    inputType.addEventListener('change', () => {
        if (inputType.value === 'email') {
            senderGroup.classList.remove('hidden');
        } else {
            senderGroup.classList.add('hidden');
            senderInput.value = '';
        }
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // UI Loading state
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        scanBtn.disabled = true;
        resultPanel.classList.add('hidden');
        notificationBanner.classList.add('hidden');
        memoryBoost.classList.add('hidden');

        // Build request payload
        const payload = {
            user_id: "frontend-demo-user",
            input_type: inputType.value,
            text: textInput.value
        };
        
        if (inputType.value === 'email' && senderInput.value) {
            payload.sender = senderInput.value;
        }

        try {
            // Because the frontend is served statically by the backend, 
            // the API is on the same origin.
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();
            displayResults(data);
        } catch (error) {
            console.error("Scan failed", error);
            alert("Analysis failed. Please check the console for details.");
        } finally {
            // Reset loading state
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
            scanBtn.disabled = false;
        }
    });

    function displayResults(data) {
        const risk = data.agent_result.risk;
        const score = risk.final_score;
        const verdict = risk.verdict;
        
        // Calculate Risk Colors
        let strokeColor = "var(--risk-low)";
        let bgColor = "rgba(16, 185, 129, 0.1)";
        
        if (score >= 80) {
            strokeColor = "var(--risk-high)";
            bgColor = "rgba(239, 68, 68, 0.1)";
        } else if (score >= 40) {
            strokeColor = "var(--risk-med)";
            bgColor = "rgba(245, 158, 11, 0.1)";
        }

        // Animate Circle
        // The stroke-dasharray is "value, 100"
        setTimeout(() => {
            scoreCircle.setAttribute('stroke-dasharray', `${score}, 100`);
            scoreCircle.style.stroke = strokeColor;
        }, 100);

        // Update Score Text
        animateValue(scoreText, 0, score, 1000);
        
        // Update Verdict Text & Badge
        verdictText.textContent = verdict.replace(/_/g, ' ');
        verdictText.style.color = strokeColor;
        verdictBadge.textContent = verdict.replace(/_/g, ' ');
        verdictBadge.style.color = strokeColor;
        verdictBadge.style.backgroundColor = bgColor;
        
        // Flagged Categories
        categoriesList.innerHTML = '';
        const flags = data.agent_result.text_analysis?.matched_categories || {};
        const flagKeys = Object.keys(flags);
        
        if (flagKeys.length > 0) {
            flagKeys.forEach(cat => {
                const li = document.createElement('li');
                li.textContent = cat;
                categoriesList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = "No specific patterns flagged";
            li.style.opacity = 0.5;
            categoriesList.appendChild(li);
        }

        // Memory Summary
        const mem = data.memory_summary;
        if (mem) {
            memoryStats.textContent = `${mem.total || 0} prior interactions, ${mem.high_risk_count || 0} high-risk`;
            if (risk.repeat_offender_boost) {
                memoryBoost.classList.remove('hidden');
                memoryBoost.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path></svg> Repeat Offender Boost: +${risk.repeat_offender_boost}pts`;
            }
        }

        // Notifications
        if (data.notification?.notified) {
            notificationBanner.classList.remove('hidden');
            notifDetails.textContent = `Alert sent to ${data.notification.guardian_notified}`;
        }

        // Show panel with transition
        resultPanel.classList.remove('hidden');
        resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Number counting animation
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
