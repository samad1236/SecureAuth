/* ==========================================================================
   SecureAuth - Google Authenticator Web Application Logic
   ========================================================================== */

// --- State Management ---
let state = {
    accounts: [],
    pin: null,
    isLocked: false,
    activeTab: 'camera-scan',
    html5QrScanner: null,
    currentCodes: {}, // Cache for current codes to avoid redundant generation
    lastTimeStep: -1, // Track last time step to know when to regenerate codes
    user: null // Logged in user details
};

// --- Constants ---
const STORAGE_KEY_ACCOUNTS = 'secureauth_accounts';
const STORAGE_KEY_PIN = 'secureauth_pin';
const STORAGE_KEY_USER = 'secureauth_registered_user';
const SESSION_KEY_LOGGED_IN = 'secureauth_session_active';

// --- Base32 Decoder ---
function base32ToBuf(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    // Clean up string: remove spaces, hyphens, padding, and convert to uppercase
    const clean = base32.replace(/[\s-]/g, "").toUpperCase().replace(/=+$/, "");
    const len = clean.length;
    let bits = 0;
    let value = 0;
    const bytes = [];

    for (let i = 0; i < len; i++) {
        const idx = alphabet.indexOf(clean[i]);
        if (idx === -1) {
            throw new Error(`Invalid Base32 character: ${clean[i]}`);
        }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return new Uint8Array(bytes);
}

// --- Core TOTP Generator (RFC 6238) ---
async function generateTOTP(secretBase32, timeStepOffset = 0) {
    try {
        const keyBytes = base32ToBuf(secretBase32);
        if (keyBytes.length === 0) return "000000";

        const epoch = Math.floor(Date.now() / 1000);
        const timeStep = Math.floor(epoch / 30) + timeStepOffset;

        // Convert time step to 8-byte big-endian buffer
        const timeBuffer = new ArrayBuffer(8);
        const view = new DataView(timeBuffer);
        const high = Math.floor(timeStep / 0x100000000);
        const low = timeStep % 0x100000000;
        view.setUint32(0, high);
        view.setUint32(4, low);

        // Import raw key bytes into Web Crypto API
        const cryptoKey = await window.crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "HMAC", hash: { name: "SHA-1" } },
            false,
            ["sign"]
        );

        // Sign the time buffer with HMAC-SHA1
        const signature = await window.crypto.subtle.sign(
            "HMAC",
            cryptoKey,
            timeBuffer
        );

        const hmacResult = new Uint8Array(signature);

        // Dynamic Truncation (RFC 4226)
        const offset = hmacResult[hmacResult.length - 1] & 0xf;
        const code = (
            ((hmacResult[offset] & 0x7f) << 24) |
            ((hmacResult[offset + 1] & 0xff) << 16) |
            ((hmacResult[offset + 2] & 0xff) << 8) |
            (hmacResult[offset + 3] & 0xff)
        ) % 1000000;

        // Pad with leading zeros to ensure 6 digits
        return code.toString().padStart(6, "0");
    } catch (e) {
        console.error("Error generating TOTP:", e);
        return "000000";
    }
}

// --- Helper: Generate Service Color ---
function getServiceColor(issuer) {
    const colors = [
        "#ef4444", "#f97316", "#f59e0b", "#10b981", 
        "#06b6d4", "#3b82f6", "#6366f1", "#8b5cf6", 
        "#ec4899", "#14b8a6"
    ];
    let hash = 0;
    const cleanIssuer = issuer.trim().toLowerCase();
    
    // Pre-defined brand colors for popular services
    if (cleanIssuer.includes("google")) return "#ea4335";
    if (cleanIssuer.includes("github")) return "#24292e";
    if (cleanIssuer.includes("discord")) return "#5865f2";
    if (cleanIssuer.includes("facebook")) return "#1877f2";
    if (cleanIssuer.includes("microsoft")) return "#00a4ef";
    if (cleanIssuer.includes("aws") || cleanIssuer.includes("amazon")) return "#ff9900";
    if (cleanIssuer.includes("dropbox")) return "#0061ff";
    if (cleanIssuer.includes("slack")) return "#4a154b";
    if (cleanIssuer.includes("twitter") || cleanIssuer.includes("x")) return "#000000";
    if (cleanIssuer.includes("steam")) return "#171a21";
    
    for (let i = 0; i < cleanIssuer.length; i++) {
        hash = cleanIssuer.charCodeAt(i) + ((hash << 5) - hash);
    }
    const index = Math.abs(hash) % colors.length;
    return colors[index];
}

// --- Helper: Parse otpauth:// URI ---
function parseOtpauthUri(uriString) {
    try {
        const url = new URL(uriString);
        if (url.protocol !== "otpauth:") {
            throw new Error("Invalid protocol. Must be otpauth://");
        }
        if (url.host !== "totp") {
            throw new Error("Only TOTP is supported.");
        }
        
        let label = decodeURIComponent(url.pathname.substring(1));
        let issuer = url.searchParams.get("issuer") || "";
        let account = label;
        
        if (label.includes(":")) {
            const parts = label.split(":");
            const pathIssuer = parts[0].trim();
            const pathAccount = parts.slice(1).join(":").trim();
            
            if (!issuer) {
                issuer = pathIssuer;
            }
            account = pathAccount;
        }
        
        const secret = url.searchParams.get("secret");
        if (!secret) {
            throw new Error("Secret key is missing in QR code.");
        }
        
        return {
            issuer: issuer || "Unknown",
            account: account || "Account",
            secret: secret.toUpperCase()
        };
    } catch (e) {
        console.error("Failed to parse OTP URI:", e);
        throw new Error("Invalid QR Code format. Could not parse 2FA credentials.");
    }
}

// --- LocalStorage Operations ---
function loadData() {
    // Load Accounts
    const storedAccounts = localStorage.getItem(STORAGE_KEY_ACCOUNTS);
    if (storedAccounts) {
        try {
            state.accounts = JSON.parse(storedAccounts);
        } catch (e) {
            console.error("Failed to parse stored accounts:", e);
            state.accounts = [];
        }
    }

    // Load PIN
    state.pin = localStorage.getItem(STORAGE_KEY_PIN);
    if (state.pin) {
        state.isLocked = true;
    }

    // Load registered user
    const storedUser = localStorage.getItem(STORAGE_KEY_USER);
    if (storedUser) {
        try {
            state.user = JSON.parse(storedUser);
        } catch (e) {
            console.error("Failed to parse stored user:", e);
            state.user = null;
        }
    }
}

function saveAccounts() {
    localStorage.setItem(STORAGE_KEY_ACCOUNTS, JSON.stringify(state.accounts));
}

// --- Toast Notification ---
function showToast(message) {
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toast-message');
    toastMsg.textContent = message;
    toast.classList.add('active');
    setTimeout(() => {
        toast.classList.remove('active');
    }, 2500);
}

// --- UI Rendering ---
async function renderAccounts() {
    const accountsList = document.getElementById('accounts-list');
    const emptyState = document.getElementById('empty-state');
    const searchInput = document.getElementById('search-input');
    const query = searchInput.value.toLowerCase().trim();

    const filteredAccounts = state.accounts.filter(acc => 
        acc.issuer.toLowerCase().includes(query) || 
        acc.account.toLowerCase().includes(query)
    );

    if (state.accounts.length === 0) {
        emptyState.classList.remove('hidden');
        accountsList.classList.add('hidden');
        return;
    }

    emptyState.classList.add('hidden');
    accountsList.classList.remove('hidden');

    // Clear list
    accountsList.innerHTML = '';

    if (filteredAccounts.length === 0) {
        accountsList.innerHTML = `
            <div class="empty-state" style="padding: 20px;">
                <div class="empty-icon" style="width: 60px; height: 60px; font-size: 24px; margin-bottom: 16px;">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </div>
                <h2>No results found</h2>
                <p>No accounts match "${searchInput.value}"</p>
            </div>
        `;
        return;
    }

    // Render each account card
    for (const acc of filteredAccounts) {
        const card = document.createElement('div');
        card.className = 'account-card';
        card.dataset.id = acc.id;

        // Get or generate code
        const code = state.currentCodes[acc.id] || "000000";
        const formattedCode = `${code.substring(0, 3)} ${code.substring(3)}`;

        const avatarColor = acc.color || getServiceColor(acc.issuer);
        const firstLetter = acc.issuer.charAt(0);

        card.innerHTML = `
            <div class="account-info-container">
                <div class="service-avatar" style="background-color: ${avatarColor};">
                    ${firstLetter}
                </div>
                <div class="account-details">
                    <div class="issuer-name">${escapeHtml(acc.issuer)}</div>
                    <div class="account-name">${escapeHtml(acc.account)}</div>
                    <div class="security-code" id="code-${acc.id}" title="Click to copy code">
                        ${formattedCode}
                    </div>
                </div>
            </div>
            <div class="card-actions">
                <div class="countdown-container">
                    <svg class="countdown-ring" width="36" height="36">
                        <circle class="countdown-ring-circle-bg" stroke-width="3" fill="transparent" r="15" cx="18" cy="18"/>
                        <circle class="countdown-ring-circle" id="ring-${acc.id}" stroke-width="3" fill="transparent" r="15" cx="18" cy="18" stroke-dasharray="94.2" stroke-dashoffset="0"/>
                    </svg>
                    <span class="countdown-text" id="text-${acc.id}">30</span>
                </div>
                <button class="action-btn copy-btn" title="Copy Code">
                    <i class="fa-solid fa-copy"></i>
                </button>
                <button class="action-btn qr-btn" title="View QR Code">
                    <i class="fa-solid fa-qrcode"></i>
                </button>
                <button class="action-btn delete-btn" title="Delete Account">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            </div>
        `;

        // Add Event Listeners to Card Buttons
        card.querySelector('.security-code').addEventListener('click', () => copyCode(acc.id));
        card.querySelector('.copy-btn').addEventListener('click', () => copyCode(acc.id));
        card.querySelector('.qr-btn').addEventListener('click', () => showAccountQr(acc));
        card.querySelector('.delete-btn').addEventListener('click', () => deleteAccount(acc.id, acc.issuer));

        accountsList.appendChild(card);
    }

    // Update the countdown rings and text immediately
    updateCountdownVisuals();
}

// --- Escape HTML to prevent XSS ---
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// --- Copy Code to Clipboard ---
function copyCode(accountId) {
    const code = state.currentCodes[accountId];
    if (!code) return;

    navigator.clipboard.writeText(code).then(() => {
        showToast("Code copied to clipboard!");
    }).catch(err => {
        console.error("Failed to copy code:", err);
        showToast("Failed to copy code.");
    });
}

// --- Delete Account ---
function deleteAccount(id, issuer) {
    if (confirm(`Are you sure you want to delete the account for "${issuer}"?\nThis action cannot be undone and you may lose access to your account if you don't have a backup!`)) {
        state.accounts = state.accounts.filter(acc => acc.id !== id);
        delete state.currentCodes[id];
        saveAccounts();
        renderAccounts();
        showToast("Account deleted.");
    }
}

// --- Show Account QR Code Modal ---
function showAccountQr(account) {
    const modal = document.getElementById('details-modal');
    const title = document.getElementById('details-title');
    const issuerVal = document.getElementById('details-issuer-val');
    const accountVal = document.getElementById('details-account-val');
    const secretVal = document.getElementById('details-secret-val');
    const copySecretBtn = document.getElementById('copy-details-secret');

    title.textContent = `${account.issuer} Details`;
    issuerVal.textContent = account.issuer;
    accountVal.textContent = account.account;
    secretVal.textContent = account.secret;

    // Generate otpauth URI
    // Format: otpauth://totp/Issuer:Account?secret=SECRET&issuer=Issuer
    const label = `${account.issuer}:${account.account}`;
    const otpauthUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(account.secret)}&issuer=${encodeURIComponent(account.issuer)}`;

    // Generate QR Code on Canvas
    const canvas = document.getElementById('details-qr-canvas');
    new QRious({
        element: canvas,
        value: otpauthUri,
        size: 250,
        level: 'M'
    });

    // Copy Secret Key Event
    copySecretBtn.onclick = () => {
        navigator.clipboard.writeText(account.secret).then(() => {
            showToast("Secret key copied!");
        });
    };

    openModal('details-modal');
}

// --- Real-time Countdown & Code Updates ---
async function updateCodesLoop() {
    // Check 5-minute session timeout
    checkSessionTimeout();

    const epoch = Math.floor(Date.now() / 1000);
    const currentStep = Math.floor(epoch / 30);

    // If the 30-second step has changed, or if it's the first run, regenerate all codes
    if (currentStep !== state.lastTimeStep) {
        state.lastTimeStep = currentStep;
        
        // Regenerate codes for all accounts
        for (const acc of state.accounts) {
            state.currentCodes[acc.id] = await generateTOTP(acc.secret);
            
            // Update the text in the DOM if it exists
            const codeEl = document.getElementById(`code-${acc.id}`);
            if (codeEl) {
                const code = state.currentCodes[acc.id];
                codeEl.textContent = `${code.substring(0, 3)} ${code.substring(3)}`;
            }
        }
    }

    updateCountdownVisuals();
}

function updateCountdownVisuals() {
    const epoch = Math.floor(Date.now() / 1000);
    const remainingSeconds = 30 - (epoch % 30);
    const isExpiring = remainingSeconds <= 5;

    // Circumference of our SVG circle is 2 * PI * 15 = 94.24
    const maxOffset = 94.24;
    const offset = (remainingSeconds / 30) * maxOffset;

    for (const acc of state.accounts) {
        const ring = document.getElementById(`ring-${acc.id}`);
        const text = document.getElementById(`text-${acc.id}`);
        const codeEl = document.getElementById(`code-${acc.id}`);

        if (ring) {
            // Animate stroke-dashoffset
            // 0 offset means full circle, maxOffset means empty circle
            // We want it to start full (0 offset) and empty out (maxOffset)
            const dashoffset = maxOffset - offset;
            ring.style.strokeDashoffset = dashoffset;

            if (isExpiring) {
                ring.classList.add('expiring');
            } else {
                ring.classList.remove('expiring');
            }
        }

        if (text) {
            text.textContent = remainingSeconds;
            if (isExpiring) {
                text.classList.add('expiring');
            } else {
                text.classList.remove('expiring');
            }
        }

        if (codeEl) {
            if (isExpiring) {
                codeEl.classList.add('expiring');
            } else {
                codeEl.classList.remove('expiring');
            }
        }
    }
}

// --- Modal Management ---
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.add('active');
    
    // If opening QR scanner modal, start camera if active tab is camera
    if (modalId === 'scan-modal' && state.activeTab === 'camera-scan') {
        startCameraScanner();
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.remove('active');

    // If closing QR scanner modal, stop camera
    if (modalId === 'scan-modal') {
        stopCameraScanner();
    }
}

// --- FAB Menu Management ---
function toggleFabMenu() {
    const fabBtn = document.getElementById('fab-btn');
    const fabMenu = document.getElementById('fab-menu');
    const fabOverlay = document.getElementById('fab-overlay');

    const isActive = fabBtn.classList.toggle('active');
    fabMenu.classList.toggle('active', isActive);
    fabOverlay.classList.toggle('active', isActive);
}

function closeFabMenu() {
    const fabBtn = document.getElementById('fab-btn');
    const fabMenu = document.getElementById('fab-menu');
    const fabOverlay = document.getElementById('fab-overlay');

    fabBtn.classList.remove('active');
    fabMenu.classList.remove('active');
    fabOverlay.classList.remove('active');
}

// --- QR Code Scanner (Camera) ---
function startCameraScanner() {
    const qrReaderContainer = document.getElementById('qr-reader-container');
    qrReaderContainer.classList.remove('hidden');

    state.html5QrScanner = new Html5Qrcode("qr-reader");
    
    const config = { 
        fps: 10, 
        qrbox: { width: 250, height: 250 },
        aspectRatio: 1.0
    };

    state.html5QrScanner.start(
        { facingMode: "environment" }, 
        config,
        onQrScanSuccess,
        onQrScanFailure
    ).catch(err => {
        console.error("Failed to start camera scanner:", err);
        document.getElementById('qr-reader').innerHTML = `
            <div class="scan-error" style="margin: 20px; height: calc(100% - 40px); display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 10px;">
                <i class="fa-solid fa-video-slash" style="font-size: 32px;"></i>
                <span>Camera access denied or unavailable.</span>
                <button class="btn btn-secondary btn-sm" onclick="switchScanTab('file-scan')">Use File Upload</button>
            </div>
        `;
    });
}

function stopCameraScanner() {
    if (state.html5QrScanner && state.html5QrScanner.isScanning) {
        state.html5QrScanner.stop().then(() => {
            state.html5QrScanner = null;
        }).catch(err => {
            console.error("Failed to stop camera scanner:", err);
        });
    }
}

function onQrScanSuccess(decodedText, decodedResult) {
    try {
        stopCameraScanner();
        closeModal('scan-modal');
        
        const parsed = parseOtpauthUri(decodedText);
        addAccount(parsed.issuer, parsed.account, parsed.secret);
        showToast(`Added account: ${parsed.issuer}`);
    } catch (e) {
        showToast(e.message || "Invalid QR Code");
        // Restart scanner after a short delay if it failed to parse but camera is still active
        setTimeout(() => {
            if (document.getElementById('scan-modal').classList.contains('active') && state.activeTab === 'camera-scan') {
                startCameraScanner();
            }
        }, 2000);
    }
}

function onQrScanFailure(error) {
    // This callback is called for every frame where no QR code is detected.
    // We can ignore it to avoid spamming the console.
}

// --- QR Code Scanner (File Upload) ---
function handleQrFileUpload(file) {
    const errorEl = document.getElementById('file-scan-error');
    errorEl.classList.add('hidden');

    if (!file) return;

    const html5QrCode = new Html5Qrcode("qr-reader");
    html5QrCode.scanFile(file, true)
        .then(decodedText => {
            const parsed = parseOtpauthUri(decodedText);
            addAccount(parsed.issuer, parsed.account, parsed.secret);
            closeModal('scan-modal');
            showToast(`Added account: ${parsed.issuer}`);
        })
        .catch(err => {
            console.error("Error scanning file:", err);
            errorEl.textContent = "Could not find a valid 2FA QR code in this image. Please try another image.";
            errorEl.classList.remove('hidden');
        });
}

function switchScanTab(tabId) {
    state.activeTab = tabId;
    
    // Update tab buttons
    document.querySelectorAll('.scan-tab').forEach(btn => {
        if (btn.dataset.tab === tabId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Update tab contents
    document.querySelectorAll('.scan-tab-content').forEach(content => {
        if (content.id === tabId) {
            content.classList.remove('hidden');
        } else {
            content.classList.add('hidden');
        }
    });

    // Handle camera start/stop
    if (tabId === 'camera-scan') {
        startCameraScanner();
    } else {
        stopCameraScanner();
    }
}

// --- Add Account ---
function addAccount(issuer, account, secret) {
    // Clean secret
    const cleanSecret = secret.replace(/[\s-]/g, "").toUpperCase();
    
    // Validate secret is valid Base32
    try {
        base32ToBuf(cleanSecret);
    } catch (e) {
        alert("Invalid Secret Key! Secret must be a valid Base32 string (A-Z, 2-7).");
        return false;
    }

    const newAccount = {
        id: Date.now().toString(),
        issuer: issuer.trim(),
        account: account.trim(),
        secret: cleanSecret,
        color: getServiceColor(issuer)
    };

    state.accounts.push(newAccount);
    saveAccounts();
    
    // Trigger immediate code generation for the new account
    generateTOTP(newAccount.secret).then(code => {
        state.currentCodes[newAccount.id] = code;
        renderAccounts();
    });

    return true;
}

// --- Backup & Restore (Download File) ---
function exportBackup() {
    try {
        if (state.accounts.length === 0) {
            showToast("No accounts to backup!");
            return;
        }

        const backupData = {
            version: 1,
            exportedAt: new Date().toISOString(),
            accounts: state.accounts
        };

        const jsonString = JSON.stringify(backupData, null, 2);
        const blob = new Blob([jsonString], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `secureauth_backup_${new Date().toISOString().slice(0,10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast("Backup downloaded successfully!");
        updateBackupStatus("Backup downloaded successfully!", "success");
    } catch (e) {
        console.error("Backup export failed:", e);
        showToast("Backup failed.");
        updateBackupStatus("Backup failed. Please try again.", "error");
    }
}

function importBackup(file) {
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            
            // Validation
            if (!data || !Array.isArray(data.accounts)) {
                throw new Error("Invalid backup file format.");
            }

            let importedCount = 0;
            let duplicateCount = 0;

            for (const importedAcc of data.accounts) {
                if (!importedAcc.issuer || !importedAcc.account || !importedAcc.secret) {
                    continue; // Skip invalid accounts
                }

                // Check for duplicates (same secret or same issuer+account)
                const isDuplicate = state.accounts.some(acc => 
                    acc.secret.replace(/[\s-]/g, "").toUpperCase() === importedAcc.secret.replace(/[\s-]/g, "").toUpperCase() ||
                    (acc.issuer.toLowerCase() === importedAcc.issuer.toLowerCase() && acc.account.toLowerCase() === importedAcc.account.toLowerCase())
                );

                if (isDuplicate) {
                    duplicateCount++;
                    continue;
                }

                state.accounts.push({
                    id: Date.now().toString() + "_" + Math.random().toString(36).substr(2, 5),
                    issuer: importedAcc.issuer,
                    account: importedAcc.account,
                    secret: importedAcc.secret.replace(/[\s-]/g, "").toUpperCase(),
                    color: importedAcc.color || getServiceColor(importedAcc.issuer)
                });
                importedCount++;
            }

            if (importedCount > 0) {
                saveAccounts();
                // Trigger code generation for all accounts
                state.lastTimeStep = -1; // Force regeneration
                updateCodesLoop().then(() => {
                    renderAccounts();
                });
                showToast(`Imported ${importedCount} accounts!`);
                updateBackupStatus(`Successfully imported ${importedCount} accounts! (Skipped ${duplicateCount} duplicates)`, "success");
            } else {
                showToast("No new accounts imported.");
                updateBackupStatus(`No new accounts imported. (Skipped ${duplicateCount} duplicates)`, "success");
            }

            // Reset file input
            document.getElementById('import-backup-input').value = '';
        } catch (err) {
            console.error("Backup import failed:", err);
            showToast("Failed to import backup.");
            updateBackupStatus("Failed to import backup. Invalid file format.", "error");
        }
    };
    reader.readAsText(file);
}

function updateBackupStatus(message, type) {
    const statusEl = document.getElementById('backup-status');
    statusEl.textContent = message;
    statusEl.className = `backup-status ${type}`;
    statusEl.classList.remove('hidden');
    setTimeout(() => {
        statusEl.classList.add('hidden');
    }, 5000);
}

// --- PIN Lock Screen Logic ---
let enteredPin = "";

function initLockScreen() {
    const lockScreen = document.getElementById('lock-screen');
    if (state.pin) {
        lockScreen.classList.remove('hidden');
        state.isLocked = true;
        enteredPin = "";
        updatePinDots();
    } else {
        lockScreen.classList.add('hidden');
        state.isLocked = false;
    }
}

function handlePinInput(val) {
    if (enteredPin.length >= 4) return;
    
    enteredPin += val;
    updatePinDots();

    if (enteredPin.length === 4) {
        // Verify PIN
        setTimeout(() => {
            if (enteredPin === state.pin) {
                // Unlock
                document.getElementById('lock-screen').classList.add('hidden');
                state.isLocked = false;
                showToast("Welcome back!");
            } else {
                // Shake and clear
                const container = document.querySelector('.lock-container');
                container.classList.add('shake');
                document.getElementById('pin-error').classList.remove('hidden');
                
                setTimeout(() => {
                    container.classList.remove('shake');
                }, 400);

                enteredPin = "";
                updatePinDots();
            }
        }, 200);
    }
}

function handlePinBackspace() {
    if (enteredPin.length > 0) {
        enteredPin = enteredPin.slice(0, -1);
        updatePinDots();
        document.getElementById('pin-error').classList.add('hidden');
    }
}

function handlePinClear() {
    enteredPin = "";
    updatePinDots();
    document.getElementById('pin-error').classList.add('hidden');
}

function updatePinDots() {
    const dots = document.querySelectorAll('.pin-dots .dot');
    dots.forEach((dot, idx) => {
        if (idx < enteredPin.length) {
            dot.classList.add('filled');
        } else {
            dot.classList.remove('filled');
        }
    });
}

function setupPinLock(pinVal) {
    localStorage.setItem(STORAGE_KEY_PIN, pinVal);
    state.pin = pinVal;
    showToast("PIN Lock enabled successfully!");
    document.getElementById('pin-lock-toggle').checked = true;
    document.getElementById('pin-setup-container').classList.add('hidden');
    
    // Clear inputs
    document.getElementById('setup-pin').value = '';
    document.getElementById('setup-pin-confirm').value = '';
}

function removePinLock() {
    localStorage.removeItem(STORAGE_KEY_PIN);
    state.pin = null;
    showToast("PIN Lock disabled.");
    document.getElementById('pin-lock-toggle').checked = false;
    document.getElementById('pin-setup-container').classList.add('hidden');
}

// --- Entering Gateway Logic ---
let isRegisterMode = true;

function initGateway() {
    const gatewayScreen = document.getElementById('gateway-screen');
    const appContainer = document.getElementById('app-container');
    const sessionActive = sessionStorage.getItem(SESSION_KEY_LOGGED_IN);

    if (sessionActive === 'true' && state.user) {
        // Already logged in for this session
        gatewayScreen.classList.add('hidden');
        if (appContainer) appContainer.classList.add('active');
        document.getElementById('user-display-name').textContent = state.user.name;
        
        // Initialize PIN lock if set
        initLockScreen();
    } else {
        // Show gateway
        gatewayScreen.classList.remove('hidden');
        if (appContainer) appContainer.classList.remove('active');
        document.getElementById('lock-screen').classList.add('hidden'); // Hide PIN lock behind gateway
        
        if (state.user) {
            // User is registered, show Login mode
            switchGatewayMode(false);
        } else {
            // No user registered, show Register mode
            switchGatewayMode(true);
        }
    }
}

function switchGatewayMode(register) {
    isRegisterMode = register;
    const title = document.getElementById('gateway-title');
    const subtitle = document.getElementById('gateway-subtitle');
    const nameGroup = document.getElementById('gateway-name-group');
    const confirmGroup = document.getElementById('gateway-confirm-group');
    const submitBtn = document.getElementById('gateway-submit-btn');
    const switchText = document.getElementById('gateway-switch-text');
    const switchLink = document.getElementById('gateway-switch-link');
    const errorEl = document.getElementById('gateway-error');

    errorEl.classList.add('hidden');

    if (register) {
        title.textContent = "Create SecureAuth Account";
        subtitle.textContent = "Register to secure your 2FA codes";
        nameGroup.classList.remove('hidden');
        document.getElementById('gateway-name').required = true;
        confirmGroup.classList.remove('hidden');
        document.getElementById('gateway-confirm-password').required = true;
        submitBtn.textContent = "Register & Enter";
        switchText.textContent = "Already have an account?";
        switchLink.textContent = "Login here";
    } else {
        title.textContent = "Welcome Back";
        subtitle.textContent = "Log in to access your 2FA codes";
        nameGroup.classList.add('hidden');
        document.getElementById('gateway-name').required = false;
        confirmGroup.classList.add('hidden');
        document.getElementById('gateway-confirm-password').required = false;
        submitBtn.textContent = "Log In";
        switchText.textContent = "Don't have an account?";
        switchLink.textContent = "Register here";
    }
}

function handleGatewaySubmit(e) {
    e.preventDefault();
    const nameInput = document.getElementById('gateway-name').value;
    const emailInput = document.getElementById('gateway-email').value.trim().toLowerCase();
    const passwordInput = document.getElementById('gateway-password').value;
    const confirmInput = document.getElementById('gateway-confirm-password').value;
    const errorEl = document.getElementById('gateway-error');

    errorEl.classList.add('hidden');

    if (isRegisterMode) {
        // Registration
        if (passwordInput.length < 6) {
            errorEl.textContent = "Password must be at least 6 characters long.";
            errorEl.classList.remove('hidden');
            return;
        }

        if (passwordInput !== confirmInput) {
            errorEl.textContent = "Passwords do not match.";
            errorEl.classList.remove('hidden');
            return;
        }

        // Save user credentials
        const newUser = {
            name: nameInput.trim(),
            email: emailInput,
            password: passwordInput // In a real app, this would be hashed on a server
        };

        localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(newUser));
        state.user = newUser;

        // Log in
        sessionStorage.setItem(SESSION_KEY_LOGGED_IN, 'true');
        sessionStorage.setItem('secureauth_login_time', Date.now().toString());
        document.getElementById('user-display-name').textContent = newUser.name;
        document.getElementById('gateway-screen').classList.add('hidden');
        const appContainer = document.getElementById('app-container');
        if (appContainer) appContainer.classList.add('active');
        showToast(`Welcome, ${newUser.name}!`);
        
        // Reset form
        document.getElementById('gateway-form').reset();
    } else {
        // Login
        if (!state.user) {
            errorEl.textContent = "No registered user found. Please register first.";
            errorEl.classList.remove('hidden');
            return;
        }

        if (emailInput === state.user.email && passwordInput === state.user.password) {
            // Successful login
            sessionStorage.setItem(SESSION_KEY_LOGGED_IN, 'true');
            sessionStorage.setItem('secureauth_login_time', Date.now().toString());
            document.getElementById('user-display-name').textContent = state.user.name;
            document.getElementById('gateway-screen').classList.add('hidden');
            const appContainer = document.getElementById('app-container');
            if (appContainer) appContainer.classList.add('active');
            showToast(`Welcome back, ${state.user.name}!`);
            
            // Initialize PIN lock if set
            initLockScreen();
            
            // Reset form
            document.getElementById('gateway-form').reset();
        } else {
            errorEl.textContent = "Invalid email or password. Please try again.";
            errorEl.classList.remove('hidden');
            
            // Shake container
            const container = document.querySelector('.gateway-container');
            container.classList.add('shake');
            setTimeout(() => {
                container.classList.remove('shake');
            }, 400);
        }
    }
}

function checkSessionTimeout() {
    const sessionActive = sessionStorage.getItem(SESSION_KEY_LOGGED_IN);
    const loginTime = sessionStorage.getItem('secureauth_login_time');
    if (sessionActive === 'true' && loginTime) {
        const elapsed = Date.now() - parseInt(loginTime, 10);
        const fiveMinutes = 5 * 60 * 1000;
        if (elapsed >= fiveMinutes) {
            performLogout(true);
        }
    }
}

function performLogout(isAuto = false) {
    sessionStorage.removeItem(SESSION_KEY_LOGGED_IN);
    sessionStorage.removeItem('secureauth_login_time');
    document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
    const appContainer = document.getElementById('app-container');
    if (appContainer) appContainer.classList.remove('active');
    initGateway();
    if (isAuto) {
        showToast("Logged out automatically after 5 minutes.");
    } else {
        showToast("Logged out successfully.");
    }
}

function handleLogout() {
    if (confirm("Are you sure you want to log out of your current session?")) {
        performLogout(false);
    }
}

// --- Event Listeners Setup ---
document.addEventListener('DOMContentLoaded', () => {
    // Load data from LocalStorage
    loadData();

    // Initialize Gateway
    initGateway();

    // Initial Render
    renderAccounts();

    // Start the 1-second loop for TOTP codes and countdowns
    updateCodesLoop();
    setInterval(updateCodesLoop, 1000);

    // --- Gateway Events ---
    const gatewayForm = document.getElementById('gateway-form');
    const gatewaySwitchLink = document.getElementById('gateway-switch-link');
    const toggleGatewayPassword = document.getElementById('toggle-gateway-password');
    const gatewayPasswordInput = document.getElementById('gateway-password');

    gatewayForm.addEventListener('submit', handleGatewaySubmit);
    
    gatewaySwitchLink.addEventListener('click', (e) => {
        e.preventDefault();
        switchGatewayMode(!isRegisterMode);
    });

    toggleGatewayPassword.addEventListener('click', () => {
        const type = gatewayPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        gatewayPasswordInput.setAttribute('type', type);
        toggleGatewayPassword.querySelector('i').classList.toggle('fa-eye');
        toggleGatewayPassword.querySelector('i').classList.toggle('fa-eye-slash');
    });

    // --- FAB Menu Events ---
    const fabBtn = document.getElementById('fab-btn');
    const fabOverlay = document.getElementById('fab-overlay');
    
    fabBtn.addEventListener('click', toggleFabMenu);
    fabOverlay.addEventListener('click', closeFabMenu);

    // --- Add Account Manual Modal ---
    const manualBtn = document.getElementById('manual-entry-btn');
    const emptyAddBtn = document.getElementById('empty-add-btn');
    const manualForm = document.getElementById('manual-form');
    const toggleSecretBtn = document.getElementById('toggle-secret-visibility');
    const secretInput = document.getElementById('manual-secret');

    const openManualModal = () => {
        closeFabMenu();
        openModal('manual-modal');
    };

    manualBtn.addEventListener('click', openManualModal);
    emptyAddBtn.addEventListener('click', openManualModal);

    manualForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const issuer = document.getElementById('manual-issuer').value;
        const account = document.getElementById('manual-account').value;
        const secret = secretInput.value;

        const success = addAccount(issuer, account, secret);
        if (success) {
            closeModal('manual-modal');
            manualForm.reset();
            showToast(`Added account: ${issuer}`);
        }
    });

    toggleSecretBtn.addEventListener('click', () => {
        const type = secretInput.getAttribute('type') === 'password' ? 'text' : 'password';
        secretInput.setAttribute('type', type);
        toggleSecretBtn.querySelector('i').classList.toggle('fa-eye');
        toggleSecretBtn.querySelector('i').classList.toggle('fa-eye-slash');
    });

    // Set secret input to password type initially for security
    secretInput.setAttribute('type', 'password');

    // --- QR Code Scanner Modal ---
    const scanQrBtn = document.getElementById('scan-qr-btn');
    scanQrBtn.addEventListener('click', () => {
        closeFabMenu();
        openModal('scan-modal');
        switchScanTab('camera-scan');
    });

    // Scan Tabs
    document.querySelectorAll('.scan-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            switchScanTab(tab.dataset.tab);
        });
    });

    // File Upload QR Scanner
    const fileUploadArea = document.getElementById('file-upload-area');
    const qrFileInput = document.getElementById('qr-file-input');

    fileUploadArea.addEventListener('click', () => qrFileInput.click());
    
    qrFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleQrFileUpload(e.target.files[0]);
        }
    });

    // Drag and Drop for File Upload
    fileUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileUploadArea.classList.add('dragover');
    });

    fileUploadArea.addEventListener('dragleave', () => {
        fileUploadArea.classList.remove('dragover');
    });

    fileUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        fileUploadArea.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleQrFileUpload(e.dataTransfer.files[0]);
        }
    });

    // --- Settings Modal ---
    const settingsBtn = document.getElementById('settings-btn');
    const pinLockToggle = document.getElementById('pin-lock-toggle');
    const pinSetupContainer = document.getElementById('pin-setup-container');
    const savePinBtn = document.getElementById('save-pin-btn');
    const clearAllBtn = document.getElementById('clear-all-btn');
    const exportBackupBtn = document.getElementById('export-backup-btn');
    const importBackupTrigger = document.getElementById('import-backup-trigger');
    const importBackupInput = document.getElementById('import-backup-input');
    const logoutBtn = document.getElementById('logout-btn');

    settingsBtn.addEventListener('click', () => {
        // Set initial toggle state
        pinLockToggle.checked = !!state.pin;
        pinSetupContainer.classList.add('hidden');
        openModal('settings-modal');
    });

    pinLockToggle.addEventListener('change', () => {
        if (pinLockToggle.checked) {
            pinSetupContainer.classList.remove('hidden');
        } else {
            if (confirm("Are you sure you want to disable the PIN lock?")) {
                removePinLock();
            } else {
                pinLockToggle.checked = true;
            }
        }
    });

    savePinBtn.addEventListener('click', () => {
        const pinVal = document.getElementById('setup-pin').value;
        const pinConfirmVal = document.getElementById('setup-pin-confirm').value;
        const errorEl = document.getElementById('pin-setup-error');

        errorEl.classList.add('hidden');

        if (!/^[0-9]{4}$/.test(pinVal)) {
            errorEl.textContent = "PIN must be exactly 4 digits.";
            errorEl.classList.remove('hidden');
            return;
        }

        if (pinVal !== pinConfirmVal) {
            errorEl.textContent = "PINs do not match.";
            errorEl.classList.remove('hidden');
            return;
        }

        setupPinLock(pinVal);
    });

    // Backup & Restore
    exportBackupBtn.addEventListener('click', exportBackup);
    importBackupTrigger.addEventListener('click', () => importBackupInput.click());
    importBackupInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            importBackup(e.target.files[0]);
        }
    });

    // Logout
    logoutBtn.addEventListener('click', handleLogout);

    // Clear All Data
    clearAllBtn.addEventListener('click', () => {
        if (confirm("CRITICAL WARNING!\n\nAre you absolutely sure you want to delete ALL accounts and settings?\nThis will permanently erase all 2FA keys and you will lose access to your accounts if you do not have backups elsewhere!\n\nType 'DELETE' to confirm.")) {
            const confirmation = prompt("Type 'DELETE' (all caps) to confirm permanent deletion:");
            if (confirmation === 'DELETE') {
                localStorage.clear();
                sessionStorage.clear();
                state.accounts = [];
                state.pin = null;
                state.isLocked = false;
                state.currentCodes = {};
                state.user = null;
                initGateway();
                renderAccounts();
                closeModal('settings-modal');
                showToast("All data has been permanently deleted.");
            } else {
                showToast("Deletion cancelled.");
            }
        }
    });

    // --- Search Functionality ---
    const searchInput = document.getElementById('search-input');
    const clearSearchBtn = document.getElementById('clear-search');

    searchInput.addEventListener('input', () => {
        if (searchInput.value.length > 0) {
            clearSearchBtn.classList.remove('hidden');
        } else {
            clearSearchBtn.classList.add('hidden');
        }
        renderAccounts();
    });

    clearSearchBtn.addEventListener('click', () => {
        searchInput.value = '';
        clearSearchBtn.classList.add('hidden');
        renderAccounts();
        searchInput.focus();
    });

    // --- Close Modal Buttons ---
    document.querySelectorAll('.close-btn, .modal .btn-secondary, .modal .btn-primary[data-modal]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.dataset.modal;
            closeModal(modalId);
        });
    });

    // Close modal when clicking outside content
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal(modal.id);
            }
        });
    });

    // --- PIN Keyboard Events ---
    document.querySelectorAll('.pin-btn[data-val]').forEach(btn => {
        btn.addEventListener('click', () => {
            handlePinInput(btn.dataset.val);
        });
    });

    document.getElementById('pin-backspace').addEventListener('click', handlePinBackspace);
    document.getElementById('pin-clear').addEventListener('click', handlePinClear);
});
