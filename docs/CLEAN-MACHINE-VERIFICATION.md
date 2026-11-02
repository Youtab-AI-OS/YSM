# YSM — Clean-Machine Verification

Purpose: prove, on a machine that has never run YSM, that a message sealed on
another machine opens correctly, and that a file survives the round trip byte for
byte.

Run this on the **target** machine after installing YSM. Copy the input file from
the machine that created it.

---

## 1. Install

Run `YSM-Setup-1.0.0-x64.exe`.

Expected: setup completes without warnings; a desktop shortcut and a Start-menu
entry appear; the app launches to **Create your account**.

What to check:

- [ ] No network prompt appears at any point
- [ ] No "this app wants to make changes" loop after the first consent
- [ ] Windows Defender SmartScreen may warn once because the installer is not
      code-signed; choosing **More info → Run anyway** is expected

## 2. Create an account on this machine

1. Enter a display name and a password (12+ characters).
2. The **Set up two-factor authentication** screen appears with a QR code.
3. Scan it into an authenticator app, or copy the 32-character key and enter it
   manually.
4. Type the 6-digit code and press **Verify and finish**.
5. **Download CSV** and **Download PDF** the recovery codes before pressing Done.

What to check:

- [ ] The QR code is a real, scannable image (not a blank square)
- [ ] The authenticator app accepts the key and produces codes
- [ ] The 6-digit code is accepted on the first or second try
- [ ] Both downloads produce files that open
- [ ] The PDF lists all 10 codes

## 3. Open a message sealed elsewhere

On the other machine, seal a message and copy **both** strings it shows:

- the reference, starting with `YSM_` (64 hex characters)
- the passphrase (32 characters)

On this machine:

1. Open the **Crypto** tab.
2. Choose **Decrypt**.
3. Paste the reference and the passphrase.
4. Press **Open**.

What to check:

- [ ] The original text appears exactly, including Persian text and punctuation
- [ ] A wrong passphrase is refused with an error and no partial content
- [ ] The passphrase box is cleared after opening

## 4. Open a file sealed elsewhere

Repeat with a file instead of text.

What to check:

- [ ] The file name shown matches the original, including its extension
- [ ] **Download** produces that file
- [ ] The downloaded file opens in its normal application
- [ ] The content is identical to the original — compare a checksum if possible

To compare checksums on Windows:

```
certutil -hashfile original.pdf SHA256
certutil -hashfile downloaded.pdf SHA256
```

Both hashes must match.

## 5. Prove the app does not reach the network

1. Disconnect the network adapter or turn off Wi-Fi.
2. Create an account, enrol 2FA, seal a message, open it, download a file.

What to check:

- [ ] Every step above still works with no network
- [ ] No error mentions a network, timeout, or server

## 6. Persian interface

Switch the language to Persian (فارسی).

What to check:

- [ ] The layout flips to right-to-left
- [ ] Persian text in a message reads right-to-left and is not reversed
- [ ] A message containing both Persian and a file name shows both correctly
- [ ] Numbers and the Persian comma display correctly

## 7. Lock behaviour

In Settings, set **Auto-lock after** to 30 s and wait.

What to check:

- [ ] The app returns to the unlock screen
- [ ] Any decrypted text and passphrase left on screen are gone
- [ ] Unlocking requires both the password and an authenticator code

---

## Reporting

If any check fails, record:

- which step
- what you expected
- what happened instead
- a screenshot if the failure is visual

Do not report a check as passing unless you performed it. A known-untested item is
safer than a false pass.
