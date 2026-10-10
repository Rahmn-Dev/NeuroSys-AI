// Sudo/crypto helpers. Extracted from templates/chat3.html.
  window.serverRsaPublicKey = null;

  // Helper: str2ab
  function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

  function pemToArrayBuffer(pem) {
    const b64Lines = pem.replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace(/\s+/g, "");
    const binaryString = window.atob(b64Lines);
    return str2ab(binaryString);
  }

  function toggleSudoPasswordVisibility() {
    const inp = document.getElementById('sudo-password-input');
    const eye = document.getElementById('sudo-password-eye');
    if (!inp) return;
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    if (eye) eye.className = show ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
  }

  async function submitSudoPassword() {    const pwdInput = document.getElementById('sudo-password-input');
    const pwd = pwdInput.value;
    if (!pwd) return;
    if (!window.serverRsaPublicKey) {
      alert("RSA Public Key not received from server yet. Please wait.");
      return;
    }

    if (!window.crypto || !window.crypto.subtle) {
      alert("Cryptography API not available. This feature requires a secure context (HTTPS or localhost).");
      return;
    }

    try {
      const keyBuffer = pemToArrayBuffer(window.serverRsaPublicKey);
      const importedKey = await window.crypto.subtle.importKey(
        "spki",
        keyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );
      const encodedPwd = new TextEncoder().encode(pwd);
      const encryptedBuf = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        encodedPwd
      );
      const encryptedBase64 = window.btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedBuf)));

      window.sreAgentWs.send(JSON.stringify({
        type: 'set_sudo_pwd',
        encrypted_password: encryptedBase64
      }));

      // The server now decrypts and validates with `sudo -v` before keeping
      // anything. Wait for sudo_pwd_saved / sudo_pwd_error above rather than
      // blindly declaring the session privileged.
      const saveBtn = document.getElementById('sudo-save-btn');
      if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fa-solid fa-spinner spin-anim"></i> Validating...';
      }
      pwdInput.value = '';
    } catch (err) {
      console.error("Encryption failed:", err);
      alert("Failed to encrypt password: " + (err.message || err.toString()));
    }
  }
