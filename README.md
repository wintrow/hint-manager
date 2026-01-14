# Password Manager

A secure, client-side password manager that stores all data locally in your browser using IndexedDB.

## Features

- **Master Password Protection**: Secure master password with PBKDF2 key derivation
- **AES-GCM Encryption**: All hints are encrypted before storage
- **Local Storage**: All data stored in browser's IndexedDB - no server, no cloud
- **Mobile-First Design**: Optimized for smartphone use with large touch targets
- **Minimalist UI**: Clean, simple interface
- **Chinese Character Support**: Full support for Chinese input
- **CRUD Operations**: Create, read, update, and delete password hints
- **Real-time Search**: Search by site or username

## Security

- Master password is never stored in plaintext
- Uses PBKDF2 (100,000 iterations) for key derivation
- AES-GCM (256-bit) encryption for all stored data
- Encryption key derived from master password and stored only in memory
- All encryption uses Web Crypto API

## Usage

1. Open `index.html` in a modern web browser
2. Set up your master password on first use
3. Add, edit, and manage your password hints
4. All data is stored locally in your browser

## Technical Details

- Pure HTML, CSS, and JavaScript (no frameworks)
- Uses IndexedDB for local storage
- Web Crypto API for encryption
- Mobile-first responsive design
- Works entirely client-side

## Browser Support

Requires a modern browser with support for:
- IndexedDB
- Web Crypto API
- ES6+ JavaScript

## License

This project is for personal use.
