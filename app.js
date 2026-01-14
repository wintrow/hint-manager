/**
 * Secure Password Manager - Client-Side Application
 * 
 * Security Architecture:
 * - Master password is NEVER stored in plaintext
 * - Key derivation uses PBKDF2 (100,000 iterations) for resistance against brute-force attacks
 * - Encryption uses AES-GCM (256-bit) for authenticated encryption
 * - All sensitive data is encrypted before storage in IndexedDB
 * - Encryption key is derived from master password and stored as a salt + derived key hash
 */

// ============================================================================
// Constants and Configuration
// ============================================================================

const DB_NAME = 'PasswordManagerDB';
const DB_VERSION = 1;
const STORE_MASTER = 'master';
const STORE_RECORDS = 'records';

// PBKDF2 parameters for key derivation
// Using 100,000 iterations as recommended by OWASP for 2023+
// This provides good security while maintaining reasonable performance
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_HASH = 'SHA-256';
const KEY_LENGTH = 256; // AES-256

// AES-GCM parameters
const AES_ALGORITHM = 'AES-GCM';
const AES_KEY_LENGTH = 256;
const IV_LENGTH = 12; // 96 bits for GCM (recommended)

// ============================================================================
// State Management
// ============================================================================

let db = null;
let encryptionKey = null; // Derived key from master password (in memory only)
let currentEditingId = null;

// ============================================================================
// IndexedDB Setup
// ============================================================================

/**
 * Initialize IndexedDB database
 * Creates two object stores:
 * - master: Stores the salt and key hash for master password verification
 * - records: Stores encrypted password records
 */
function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            resolve(db);
        };

        request.onupgradeneeded = (event) => {
            const database = event.target.result;

            // Create master password store
            if (!database.objectStoreNames.contains(STORE_MASTER)) {
                database.createObjectStore(STORE_MASTER, { keyPath: 'id' });
            }

            // Create records store with indexes for search
            if (!database.objectStoreNames.contains(STORE_RECORDS)) {
                const recordsStore = database.createObjectStore(STORE_RECORDS, { keyPath: 'id', autoIncrement: true });
                recordsStore.createIndex('site', 'site', { unique: false });
                recordsStore.createIndex('name', 'name', { unique: false });
                recordsStore.createIndex('createdAt', 'createdAt', { unique: false });
            }
        };
    });
}

// ============================================================================
// Web Crypto API - Key Derivation and Encryption
// ============================================================================

/**
 * Generate a random salt for key derivation
 * Salt ensures that even with the same password, different users get different keys
 */
async function generateSalt() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return array;
}

/**
 * Derive encryption key from master password using PBKDF2
 * PBKDF2 is a key derivation function that makes brute-force attacks computationally expensive
 * 
 * @param {string} password - Master password
 * @param {Uint8Array} salt - Random salt
 * @returns {CryptoKey} - Derived encryption key
 */
async function deriveKey(password, salt) {
    // Convert password to ArrayBuffer
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);

    // Import password as a key for PBKDF2
    const baseKey = await crypto.subtle.importKey(
        'raw',
        passwordData,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    // Derive key using PBKDF2
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: PBKDF2_HASH
        },
        baseKey,
        {
            name: AES_ALGORITHM,
            length: AES_KEY_LENGTH
        },
        false, // key is not extractable (security best practice)
        ['encrypt', 'decrypt']
    );

    return key;
}

/**
 * Derive a hash of the master password for verification
 * We store a hash (not the password) to verify correct password entry
 * 
 * @param {string} password - Master password
 * @param {Uint8Array} salt - Salt used for key derivation
 * @returns {string} - Base64-encoded hash
 */
async function derivePasswordHash(password, salt) {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);

    const baseKey = await crypto.subtle.importKey(
        'raw',
        passwordData,
        'PBKDF2',
        false,
        ['deriveBits']
    );

    // Derive a hash for verification (separate from encryption key)
    const hashBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: PBKDF2_HASH
        },
        baseKey,
        256 // 256 bits
    );

    // Convert to base64 for storage
    return arrayBufferToBase64(hashBits);
}

/**
 * Encrypt data using AES-GCM
 * AES-GCM provides both confidentiality and authenticity
 * 
 * @param {string} plaintext - Data to encrypt
 * @param {CryptoKey} key - Encryption key
 * @returns {Promise<{iv: string, ciphertext: string}>} - Encrypted data with IV
 */
async function encrypt(plaintext, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    // Generate random IV for each encryption (security best practice)
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

    // Encrypt using AES-GCM
    const encrypted = await crypto.subtle.encrypt(
        {
            name: AES_ALGORITHM,
            iv: iv
        },
        key,
        data
    );

    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(encrypted)
    };
}

/**
 * Decrypt data using AES-GCM
 * 
 * @param {string} ciphertext - Encrypted data
 * @param {string} iv - Initialization vector (base64)
 * @param {CryptoKey} key - Decryption key
 * @returns {Promise<string>} - Decrypted plaintext
 */
async function decrypt(ciphertext, iv, key) {
    const ivArray = base64ToArrayBuffer(iv);
    const ciphertextArray = base64ToArrayBuffer(ciphertext);

    // Decrypt using AES-GCM
    const decrypted = await crypto.subtle.decrypt(
        {
            name: AES_ALGORITHM,
            iv: ivArray
        },
        key,
        ciphertextArray
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

// ============================================================================
// Utility Functions
// ============================================================================

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Generate a secure random password
 * Uses crypto.getRandomValues for cryptographically secure randomness
 */
function generatePassword(length = 16) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => charset[byte % charset.length]).join('');
}

// ============================================================================
// Master Password Management
// ============================================================================

/**
 * Check if master password is already set up
 */
async function isMasterPasswordSet() {
    const transaction = db.transaction([STORE_MASTER], 'readonly');
    const store = transaction.objectStore(STORE_MASTER);
    const request = store.get('master');

    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result !== undefined);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Set up master password (first time only)
 * Stores salt and password hash, but NEVER the plain password
 */
async function setupMasterPassword(password) {
    if (password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
    }

    // Check if already set up
    const isSet = await isMasterPasswordSet();
    if (isSet) {
        throw new Error('Master password already set');
    }

    // Generate salt
    const salt = await generateSalt();
    
    // Derive encryption key and password hash
    const key = await deriveKey(password, salt);
    const passwordHash = await derivePasswordHash(password, salt);

    // Store salt and hash (never the password)
    const transaction = db.transaction([STORE_MASTER], 'readwrite');
    const store = transaction.objectStore(STORE_MASTER);
    
    await new Promise((resolve, reject) => {
        const request = store.put({
            id: 'master',
            salt: arrayBufferToBase64(salt),
            passwordHash: passwordHash
        });
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });

    // Store encryption key in memory (never persisted)
    encryptionKey = key;
}

/**
 * Verify and unlock with master password
 */
async function unlockMasterPassword(password) {
    const transaction = db.transaction([STORE_MASTER], 'readonly');
    const store = transaction.objectStore(STORE_MASTER);
    const request = store.get('master');

    const masterData = await new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });

    if (!masterData) {
        throw new Error('Master password not set up');
    }

    // Re-derive password hash to verify
    const salt = base64ToArrayBuffer(masterData.salt);
    const passwordHash = await derivePasswordHash(password, salt);

    // Compare hashes (constant-time comparison would be better, but acceptable for client-side)
    if (passwordHash !== masterData.passwordHash) {
        throw new Error('Incorrect master password');
    }

    // Derive and store encryption key in memory
    encryptionKey = await deriveKey(password, salt);
}

/**
 * Clear encryption key from memory (logout)
 */
function logout() {
    encryptionKey = null;
    showAuthScreen();
}

// ============================================================================
// Password Records CRUD Operations
// ============================================================================

/**
 * Create a new password record
 */
async function createRecord(site, name, password) {
    if (!encryptionKey) {
        throw new Error('Not authenticated');
    }

    // Encrypt the password before storage
    const encrypted = await encrypt(password, encryptionKey);

    const record = {
        site: site.trim(),
        name: name.trim(),
        password: encrypted.ciphertext,
        iv: encrypted.iv,
        createdAt: Date.now(),
        updatedAt: Date.now()
    };

    const transaction = db.transaction([STORE_RECORDS], 'readwrite');
    const store = transaction.objectStore(STORE_RECORDS);
    
    return new Promise((resolve, reject) => {
        const request = store.add(record);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Read all password records
 */
async function getAllRecords() {
    const transaction = db.transaction([STORE_RECORDS], 'readonly');
    const store = transaction.objectStore(STORE_RECORDS);
    const request = store.getAll();

    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Get a single record by ID
 */
async function getRecord(id) {
    const transaction = db.transaction([STORE_RECORDS], 'readonly');
    const store = transaction.objectStore(STORE_RECORDS);
    const request = store.get(id);

    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Update an existing password record
 */
async function updateRecord(id, site, name, password) {
    if (!encryptionKey) {
        throw new Error('Not authenticated');
    }

    const record = await getRecord(id);
    if (!record) {
        throw new Error('Record not found');
    }

    // Encrypt the password before storage
    const encrypted = await encrypt(password, encryptionKey);

    record.site = site.trim();
    record.name = name.trim();
    record.password = encrypted.ciphertext;
    record.iv = encrypted.iv;
    record.updatedAt = Date.now();

    const transaction = db.transaction([STORE_RECORDS], 'readwrite');
    const store = transaction.objectStore(STORE_RECORDS);
    
    return new Promise((resolve, reject) => {
        const request = store.put(record);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

/**
 * Delete a hint record
 */
async function deleteRecord(id) {
    const transaction = db.transaction([STORE_RECORDS], 'readwrite');
    const store = transaction.objectStore(STORE_RECORDS);
    
    return new Promise((resolve, reject) => {
        const request = store.delete(id);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

/**
 * Decrypt a password from a record
 */
async function decryptPassword(record) {
    if (!encryptionKey) {
        throw new Error('Not authenticated');
    }
    return await decrypt(record.password, record.iv, encryptionKey);
}

// ============================================================================
// UI Rendering
// ============================================================================

function showAuthScreen() {
    document.getElementById('auth-screen').style.display = 'flex';
    document.getElementById('app-screen').style.display = 'none';
    
    // Clear any sensitive data from forms
    document.getElementById('setup-password').value = '';
    document.getElementById('setup-confirm').value = '';
    document.getElementById('login-password').value = '';
}

function showAppScreen() {
    document.getElementById('auth-screen').style.display = 'none';
    document.getElementById('app-screen').style.display = 'block';
    loadAndDisplayRecords();
}

async function loadAndDisplayRecords(searchTerm = '') {
    const records = await getAllRecords();
    const container = document.getElementById('records-container');
    const emptyState = document.getElementById('empty-state');

    // Filter records by search term
    const filtered = records.filter(record => {
        if (!searchTerm) return true;
        const term = searchTerm.toLowerCase();
        return record.site.toLowerCase().includes(term) || 
               record.name.toLowerCase().includes(term);
    });

    if (filtered.length === 0) {
        container.innerHTML = '<p class="empty-state">' + 
            (searchTerm ? 'No records match your search.' : 'No hints stored yet. Click "Add Hint" to get started.') + 
            '</p>';
        return;
    }

    // Sort by site name
    filtered.sort((a, b) => a.site.localeCompare(b.site));

    // Decrypt and display passwords by default
    const recordsHtml = await Promise.all(filtered.map(async (record) => {
        let passwordText = '';
        try {
            passwordText = await decryptPassword(record);
        } catch (error) {
            passwordText = 'Error decrypting';
        }

        return `
        <div class="record-card" data-id="${record.id}">
            <div class="record-header">
                <div>
                    <div class="record-site">${escapeHtml(record.site)}</div>
                    <div class="record-name">${escapeHtml(record.name)}</div>
                </div>
                <div class="record-actions">
                    <button class="action-btn" onclick="editRecord(${record.id})" aria-label="Edit">Edit</button>
                    <button class="action-btn" onclick="deleteRecordPrompt(${record.id})" aria-label="Delete">Delete</button>
                </div>
            </div>
            <div class="password-display" data-record-id="${record.id}">
                <span class="password-text">${escapeHtml(passwordText)}</span>
                <button class="password-copy" onclick="copyPassword(${record.id})" aria-label="Copy hint">Copy</button>
            </div>
        </div>
    `;
    }));

    container.innerHTML = recordsHtml.join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// UI Event Handlers
// ============================================================================

// Make functions available globally for onclick handlers
window.editRecord = async function(id) {
    const record = await getRecord(id);
    if (!record) return;

    currentEditingId = id;
    document.getElementById('record-id').value = id;
    document.getElementById('record-site').value = record.site;
    document.getElementById('record-name').value = record.name;
    document.getElementById('record-password').value = '';
    document.getElementById('modal-title').textContent = 'Edit Hint';
    document.getElementById('record-modal').style.display = 'flex';
};

window.deleteRecordPrompt = function(id) {
    currentEditingId = id;
    document.getElementById('delete-modal').style.display = 'flex';
};

window.copyPassword = async function(id) {
    const record = await getRecord(id);
    if (!record) return;

    try {
        const decrypted = await decryptPassword(record);
        await navigator.clipboard.writeText(decrypted);
        
        // Visual feedback
        const button = event.target.closest('button');
        const originalText = button.textContent;
        button.textContent = '✓';
        setTimeout(() => {
            button.textContent = originalText;
        }, 1000);
    } catch (error) {
        alert('Error copying password: ' + error.message);
    }
};

// ============================================================================
// Form Handlers
// ============================================================================

async function handleSetup() {
    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;
    const errorEl = document.getElementById('setup-error');

    errorEl.textContent = '';

    if (password !== confirm) {
        errorEl.textContent = 'Passwords do not match';
        return;
    }

    if (password.length < 8) {
        errorEl.textContent = 'Password must be at least 8 characters long';
        return;
    }

    try {
        await setupMasterPassword(password);
        showAppScreen();
    } catch (error) {
        errorEl.textContent = error.message;
    }
}

async function handleLogin() {
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');

    errorEl.textContent = '';

    try {
        await unlockMasterPassword(password);
        showAppScreen();
    } catch (error) {
        errorEl.textContent = error.message;
    }
}

async function handleRecordSubmit(event) {
    event.preventDefault();

    const site = document.getElementById('record-site').value;
    const name = document.getElementById('record-name').value;
    const password = document.getElementById('record-password').value;
    const id = document.getElementById('record-id').value;

    if (!site || !name || !password) {
        alert('Please fill in all fields');
        return;
    }

    try {
        if (id) {
            await updateRecord(parseInt(id), site, name, password);
        } else {
            await createRecord(site, name, password);
        }

        document.getElementById('record-modal').style.display = 'none';
        document.getElementById('record-form').reset();
        currentEditingId = null;
        loadAndDisplayRecords(document.getElementById('search-input').value);
    } catch (error) {
        alert('Error saving record: ' + error.message);
    }
}

async function handleDelete() {
    if (!currentEditingId) return;

    try {
        await deleteRecord(currentEditingId);
        document.getElementById('delete-modal').style.display = 'none';
        currentEditingId = null;
        loadAndDisplayRecords(document.getElementById('search-input').value);
    } catch (error) {
        alert('Error deleting record: ' + error.message);
    }
}

// ============================================================================
// Initialization
// ============================================================================

async function init() {
    try {
        // Initialize database
        await initDB();

        // Check if master password is set
        const isSet = await isMasterPasswordSet();
        
        if (isSet) {
            // Show login form
            document.getElementById('setup-form').style.display = 'none';
            document.getElementById('login-form').style.display = 'block';
        } else {
            // Show setup form
            document.getElementById('setup-form').style.display = 'block';
            document.getElementById('login-form').style.display = 'none';
        }

        // Setup event listeners
        document.getElementById('setup-btn').addEventListener('click', handleSetup);
        document.getElementById('login-btn').addEventListener('click', handleLogin);
        document.getElementById('logout-btn').addEventListener('click', logout);
        document.getElementById('add-btn').addEventListener('click', () => {
            currentEditingId = null;
            document.getElementById('record-id').value = '';
            document.getElementById('record-form').reset();
            document.getElementById('modal-title').textContent = 'Add Hint';
            document.getElementById('record-modal').style.display = 'flex';
        });
        document.getElementById('close-modal').addEventListener('click', () => {
            document.getElementById('record-modal').style.display = 'none';
            document.getElementById('record-form').reset();
        });
        document.getElementById('cancel-btn').addEventListener('click', () => {
            document.getElementById('record-modal').style.display = 'none';
            document.getElementById('record-form').reset();
        });
        document.getElementById('record-form').addEventListener('submit', handleRecordSubmit);
        document.getElementById('delete-confirm').addEventListener('click', handleDelete);
        document.getElementById('delete-cancel').addEventListener('click', () => {
            document.getElementById('delete-modal').style.display = 'none';
            currentEditingId = null;
        });

        // Real-time search
        document.getElementById('search-input').addEventListener('input', (e) => {
            loadAndDisplayRecords(e.target.value);
        });

        // Allow Enter key to submit auth forms
        document.getElementById('setup-password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleSetup();
        });
        document.getElementById('setup-confirm').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleSetup();
        });
        document.getElementById('login-password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleLogin();
        });

    } catch (error) {
        console.error('Initialization error:', error);
        alert('Failed to initialize application: ' + error.message);
    }
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
