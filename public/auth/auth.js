document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("authForm");
    const formTitle = document.querySelector('h2');
    const formSubtitle = document.querySelector('.subtitle');
    const toggleMode = document.getElementById("toggleMode");
    const usernameField = document.querySelector(".username-field");
    let isLoginMode = true;

    toggleMode.addEventListener("click", (e) => {
        e.preventDefault();
        isLoginMode = !isLoginMode;
        if (isLoginMode) {
        formTitle.textContent = 'Welcome back!';
        formSubtitle.textContent = "We're so excited to see you again!";
        toggleMode.textContent = 'Register';
        usernameField.style.display = 'none';
        } else {
        formTitle.textContent = 'Create an account';
        formSubtitle.textContent = "We hope you enjoy your time here!";
        toggleMode.textContent = 'I already have an account';
        usernameField.style.display = 'block';
        }
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        const username = document.getElementById("username").value;

        // PKDF secret key
        // (register) generate assym key pair and encrypt private with secret key
        // (login) ask server for encrypted private key, decrypt it, and use it to decrypt secret value that server sends

        if (isLoginMode) {
            const endpoint = "/api/login";
            const data = { email };

            try {
                const response = await sendData(endpoint, data);
                if (response.ok) {
                    const result = await response.json();
                    const publicKey = result.publicKey;
                    const privateKey = await decryptWithPassword(password, result.encryptedPrivateKey, result.salt, result.iv);
                    const authResponse = await authenticate(email, privateKey, result.secret);
                    if (authResponse.ok) {
                        console.log("Success:", result);
                        alert("Login successful!");
                        sessionStorage.setItem("publicKey", ab2str(publicKey));
                        sessionStorage.setItem("privateKey", ab2str(privateKey));
                        window.location.href = "/chat";
                    } else {
                        const error = authResponse.json();
                        console.log("Error:", error);
                        alert("Login failed: " + error.error);
                    }
                } else {
                    const error = await response.json();
                    console.error("Error:", error);
                    alert("Login failed: " + error.error);
                }
            } catch (error) {
                console.error("Error:", error);
                alert("An error occurred. Please try again.");
            }

        } else {
            const [publicKey, privateKey] = await generateKeys();
            const publicKeyPem = toPEM(publicKey, "PUBLIC KEY");
            const [encryptedPrivateKey, salt, iv] = await encryptWithPassword(password, privateKey);

            const endpoint = "/api/register";
            const data = { email, username, privateKey: encryptedPrivateKey, publicKey: publicKeyPem, salt, iv };

            try {
                const response = await sendData(endpoint, data);
                if (response.ok) {
                    const result = await response.json();
                    // console.log("STARTSECRET:" + result.secret + ":ENDSECRET")
                    const authResponse = await authenticate(email, privateKey, result.secret);
                    if (authResponse.ok) {
                        console.log("Success:", result);
                        alert("Registration successful!");
                        sessionStorage.setItem("publicKey", ab2str(publicKey));
                        sessionStorage.setItem("privateKey", ab2str(privateKey));
                        window.location.href = "/chat";
                    } else {
                        const error = authResponse.json();
                        console.log("Error:", error);
                        alert("Registration failed: " + error.error);
                    }
                } else {
                    const error = await response.json();
                    console.error("Error:", error);
                    alert("Registration failed: " + error.error);
                }
            } catch (error) {
                console.error("Error:", error);
                alert("An error occurred. Please try again.");
            }
        }
    });
});

async function authenticate(email, privateKeyBytes, encryptedSecret) {
    const encryptedBuffer = str2ab(atob(encryptedSecret));
    const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyBytes,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedBuffer
    );

    secret = btoa(ab2str(decrypted));
    // console.log("computed secret:" + secret);

    const endpoint = "/api/authenticate";
    const data = { email, secret };

    return await sendData(endpoint, data);
}

async function sendData(endpoint, data) {
    return await fetch(endpoint, {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
    });
}

async function generateKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);

    return [publicKey, privateKey];
}

function toPEM(buffer, label) {
    const base64 = btoa(ab2str(buffer));
    return `-----BEGIN ${label}-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
}

async function encryptWithPassword(password, data) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return [btoa(ab2str(ciphertext)), btoa(ab2str(salt)), btoa(ab2str(iv))];
}

async function decryptWithPassword(password, encrypted, saltB64, ivB64) {
  const salt = str2ab(atob(saltB64));
  const iv = str2ab(atob(ivB64));
  const key = await deriveKey(password, salt);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    str2ab(atob(encrypted))
  );

  return decrypted;
}

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) bufView[i] = str.charCodeAt(i);
    return buf;
}

function ab2str(buf) {
  return String.fromCharCode(...new Uint8Array(buf));
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}