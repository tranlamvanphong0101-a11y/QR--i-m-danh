function getSessionId() {
    // Check URL hash first (from QR redirect)
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const hashSession = hashParams.get('sessionId');
    
    if (hashSession) return hashSession;
    
    // Fallback to query parameter
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('sessionId');
}

const sessionId = getSessionId();
const ticket = new URLSearchParams(window.location.search).get('ticket') || '';
// "Cấu hình máy" không phụ thuộc trình duyệt: dùng để phát hiện cùng một điện thoại mở bằng nhiều trình duyệt
function getGpuInfo() {
    try {
        var c = document.createElement('canvas');
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        var ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) return gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) + '|' + gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
    } catch (e) {}
    return '';
}

// Thông tin thiết bị để máy chủ phát hiện máy tính giả làm điện thoại / giả lập
function getEnvInfo(priv) {
    return {
        platform: String(navigator.platform || ''),
        gpu: getGpuInfo().slice(0, 200),
        touch: typeof navigator.maxTouchPoints === 'number' ? navigator.maxTouchPoints : undefined,
        priv: priv || 'unknown'
    };
}

// Lấy vị trí nhiều lần trong khoảng 3 giây (vị trí thật luôn dao động nhẹ, vị trí giả thường đứng yên tuyệt đối)
function collectLocation() {
    return new Promise(function (resolve, reject) {
        if (!navigator.geolocation) return reject(new Error('nogeo'));
        var samples = [], done = false, endTimer = null, hardTimer = null, watchId = null;
        function finish() {
            if (done) return;
            done = true;
            if (watchId !== null) navigator.geolocation.clearWatch(watchId);
            clearTimeout(endTimer); clearTimeout(hardTimer);
            if (samples.length) resolve(samples); else reject(new Error('timeout'));
        }
        watchId = navigator.geolocation.watchPosition(function (p) {
            samples.push({ lat: p.coords.latitude, lng: p.coords.longitude, acc: p.coords.accuracy });
            if (samples.length === 1) endTimer = setTimeout(finish, 3000);
            if (samples.length >= 5) finish();
        }, function (err) {
            if (!samples.length && !done) {
                done = true;
                if (watchId !== null) navigator.geolocation.clearWatch(watchId);
                clearTimeout(hardTimer);
                reject(err);
            }
        }, { enableHighAccuracy: true, maximumAge: 0, timeout: 15000 });
        hardTimer = setTimeout(finish, 16000);
    });
}

function getDeviceGroup() {
    try {
        var gpu = getGpuInfo();
        var parts = [
            Math.max(screen.width, screen.height) + 'x' + Math.min(screen.width, screen.height),
            window.devicePixelRatio || 1,
            navigator.hardwareConcurrency || 0,
            navigator.maxTouchPoints || 0,
            screen.colorDepth || 0,
            navigator.platform || '',
            Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            gpu
        ].join('|');
        var h = 5381;
        for (var i = 0; i < parts.length; i++) { h = ((h * 33) ^ parts.charCodeAt(i)) >>> 0; }
        return h.toString(16).padStart(8, '0');
    } catch (e) {
        return '';
    }
}

async function generateDeviceFingerprint() {
    try {
        // Cache fingerprint for the day to avoid recomputation
        const today = new Date().toISOString().split('T')[0];
        const cacheKey = `fingerprint-${today}`;
        const cachedFingerprint = localStorage.getItem(cacheKey);
        if (cachedFingerprint) return cachedFingerprint;

        // Collect device characteristics (same as before)
        const fingerprintData = {
            userAgent: navigator.userAgent,
            screenResolution: `${window.screen.width}x${window.screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            deviceMemory: navigator.deviceMemory || 'unknown',
            touchSupport: 'ontouchstart' in window,
            dateSalt: today
        };
        
        // Add canvas fingerprint (same as before)
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 100;
            canvas.height = 30;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("Fingerprint", 2, 15);
            fingerprintData.canvasHash = canvas.toDataURL();
        } catch (e) {
            console.log("Canvas fingerprint failed:", e);
        }
        
        // Call Java implementation via API
        const fingerprintString = JSON.stringify(fingerprintData);
        const response = await fetch('/api/consistent-hash', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ input: fingerprintString })
        });
        
        if (!response.ok) throw new Error("Hash API failed");
        const { fingerprint } = await response.json();

        // Cache the fingerprint
        localStorage.setItem(cacheKey, fingerprint);
        return fingerprint;
    } catch (error) {
        console.error("Fingerprint generation error:", error);
        // Fallback to simpler fingerprint
        return btoa(JSON.stringify({
            userAgent: navigator.userAgent,
            screenResolution: `${window.screen.width}x${window.screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            salt: "fallback-" + new Date().toISOString().split('T')[0]
        }));
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("attendanceForm");
    const statusElement = document.getElementById("status");
    const submitButton = form.querySelector("button[type='submit']");
    const API_ENDPOINT = "/mark-attendance";
    const SHOW_DASHBOARD = false; // đổi thành true khi muốn cho sinh viên vào dashboard
    let isSubmitting = false;

    // Dashboard button handler
    document.getElementById('view-dashboard-btn').addEventListener('click', function() {
        const rollNo = document.getElementById('rollInput').value.trim();
        if (!rollNo) {
            document.getElementById('accessMessage').textContent = 'Please enter your roll number';
            document.getElementById('accessMessage').className = 'text-sm text-center mt-4 text-red-600';
            return;
        }
        window.location.href = `/dashboard.html?rollNo=${encodeURIComponent(rollNo)}`;
    });

    function setStatus(text, color) {
        statusElement.innerText = text;
        statusElement.className = "text-center mt-4 text-sm " + (color || "text-red-600");
    }
    function resetButton() {
        isSubmitting = false;
        submitButton.disabled = false;
        submitButton.innerHTML = `✅ Xác nhận điểm danh`;
    }

    function showSuccess(name, universityRollNo, school) {
        document.getElementById("okName").textContent = name;
        document.getElementById("okId").textContent = universityRollNo;
        document.getElementById("okSchool").textContent = school;
        document.getElementById("okTime").textContent = new Date().toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", timeZone: "Asia/Ho_Chi_Minh" });
        form.classList.add("hidden");
        statusElement.innerText = "";
        var lb = document.getElementById("locBox"); if (lb) lb.classList.add("hidden");
        document.getElementById("successScreen").classList.remove("hidden");
        window.scrollTo(0, 0);
        if (navigator.vibrate) { try { navigator.vibrate(200); } catch (e) {} }
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (isSubmitting) return;

        if (!sessionId || !ticket) {
            setStatus("Hãy dùng camera quét trực tiếp mã QR đang chiếu trên màn hình");
            return;
        }

        const name = document.getElementById("name").value.trim();
        const universityRollNo = document.getElementById("universityRollNo").value.replace(/\s+/g, "").toUpperCase();
        const school = document.getElementById("school").value;
        if (!school || !name || !universityRollNo) {
            setStatus("Vui lòng chọn trường và điền đủ họ tên, mã số sinh viên");
            return;
        }

        isSubmitting = true;
        submitButton.disabled = true;
        submitButton.innerHTML = `Đang kiểm tra...`;

        try {
            // Chặn tab ẩn danh / riêng tư
            const priv = window.__privateCheck ? await window.__privateCheck : 'unknown';
            if (priv === 'private') {
                setStatus("Bạn đang mở tab ẩn danh / riêng tư. Hãy mở trình duyệt bình thường rồi quét lại mã.");
                resetButton();
                return;
            }

            const validationResponse = await fetch('/api/validate-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId, ticket })
            });
            const validationData = await validationResponse.json().catch(() => ({}));
            if (!validationData.valid) {
                setStatus(validationData.message || "Mã QR không hợp lệ hoặc đã hết hạn. Hãy quét lại.");
                resetButton();
                return;
            }

            const fingerprint = await generateDeviceFingerprint();

            submitButton.innerHTML = `Đang lấy vị trí...`;
            let samples;
            try {
                samples = await collectLocation();
            } catch (geoErr) {
                setStatus("Không lấy được vị trí. Hãy bật GPS và cho phép vị trí rồi thử lại.");
                resetButton();
                return;
            }
            // Dùng lần đo chính xác nhất
            const best = samples.slice().sort((a, b) => (a.acc || 9999) - (b.acc || 9999))[0];

            submitButton.innerHTML = `Đang gửi...`;
            const payload = {
                name,
                universityRollNo,
                school,
                location: { lat: best.lat, lng: best.lng, acc: best.acc },
                samples,
                deviceFingerprint: fingerprint,
                deviceGroup: getDeviceGroup(),
                env: getEnvInfo(priv),
                sessionId,
                ticket
            };

            const response = await fetch(API_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await response.json().catch(() => ({}));

            if (response.status === 400 && (data.message === "Attendance already marked today" || data.message === "Bạn đã điểm danh hôm nay rồi")) {
                setStatus("Bạn đã điểm danh hôm nay rồi", "text-yellow-600");
                if (SHOW_DASHBOARD) window.location.href = `/dashboard.html?rollNo=${encodeURIComponent(universityRollNo)}`;
                resetButton();
                return;
            }
            if (!response.ok) throw new Error(data.message || "Điểm danh không thành công");

            if (SHOW_DASHBOARD) {
                window.location.href = `/dashboard.html?rollNo=${encodeURIComponent(universityRollNo)}`;
            } else {
                showSuccess(name, universityRollNo, school);
            }
            resetButton();
        } catch (err) {
            console.error("Attendance error:", err);
            setStatus(err && err.message ? err.message : "Có lỗi xảy ra, hãy thử lại.");
            resetButton();
        }
    });
});