let messages = {}; //* dict of channelId to array of {messageId, username, message}
let keys = {}; //* dict of channelID to channelKey
let users = {}; //* dict of channelId to array of usernames
let myUsername = "";
let currentChannel = "";
const token = getCookie("sessionToken");
if (token === "") {
  alert("Invalid token, please login again.");
  document.location.href = "/";
}
// console.log(token);
const socket = new WebSocket(`ws://localhost:8080/ws/${token}`);
socket.onmessage = async (event) => {
  const data = JSON.parse(event.data);
  switch (data.action) {
    case "message":
      await handleMessage(data.channelId, data.arg1, data.arg2, data.arg3, data.arg4);
      break;
    case "edit":
      await handleEdit(data.channelId, data.arg1, data.arg2);
      break;
    case "delete":
      handleDelete(data.channelId, data.arg1);
      break;
    case "subscribe":
      await handleSubscribe(data.channelId, data.arg1, data.arg2);
      break;
    case "createChannel":
      await handleCreateChannel(data.channelId, data.arg1, data.arg2, data.arg3);
      break;
    case "deleteChannel":
      handleDeleteChannel(data.channelId);
      break;
  }
};

document.addEventListener("DOMContentLoaded", () => {
  const createChannelForm = document.querySelector(".create-channel-form");
  const newChannelInput = document.querySelector(".new-channel-input");
  const channelList = document.querySelector(".channel-list");
  const messageList = document.querySelector(".messages");
  const channelContextMenu = document.querySelector(".channel-menu");
  const messageContextMenu = document.querySelector(".message-menu");
  const deleteChannelOption = document.querySelector(".delete-channel");
  const editMessageOption = document.querySelector(".edit-message");
  const deleteMessageOption = document.querySelector(".delete-message");
  const messageInputField = document.querySelector(".message-input-field");
  const editInputField = document.querySelector(".edit-input-field");

  // Create new channel
  createChannelForm.addEventListener("submit", async (e) => {
    const channelKey = await generateChannelKey();
    const encryptedChannelKey = await encryptChannelKey(channelKey, str2ab(sessionStorage.getItem("publicKey")));
    e.preventDefault();
    const newChannelName = newChannelInput.value.trim();
    if (newChannelName) {
      createChannel(newChannelName, encryptedChannelKey);
      newChannelInput.value = "";
    }
  });

  // Context menu for channels
  channelList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const clickedChannel = e.target;
    if (clickedChannel && clickedChannel.classList.contains("channel") && clickedChannel.id !== currentChannel) {
      channelContextMenu.style.display = "block";
      channelContextMenu.style.left = `${e.pageX}px`;
      channelContextMenu.style.top = `${e.pageY}px`;
      deleteChannelOption.onclick = () => {
        deleteChannel(clickedChannel.id);
      };
    }
  });

  // Context menu for messages
  messageList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const clickedMessage = e.target;
    if (clickedMessage === null || !clickedMessage.classList.contains("message")) {
      return;
    }
    const messageBlock = e.target.closest(".message-block");
    const username = messageBlock.firstElementChild;
    const messageRect = clickedMessage.getBoundingClientRect();
    if (username && username.textContent === myUsername) {
      messageContextMenu.style.display = "block";
      messageContextMenu.style.left = `${e.pageX}px`;
      messageContextMenu.style.top = `${e.pageY}px`;
      editMessageOption.onclick = () => {
        summonEditInput(clickedMessage.textContent, messageRect, messageBlock.id);
      };
      deleteMessageOption.onclick = () => {
        deleteMessage(messageBlock.id);
      };
    }
  });

  // Hide context menu when clicking outside
  document.addEventListener("click", () => {
    channelContextMenu.style.display = "none";
    messageContextMenu.style.display = "none";
  });

  messageInputField.addEventListener("keypress", async function (event) {
    // If the user presses the "Enter" key on the keyboard
    if (event.key === "Enter") {
      // Cancel the default action, if needed
      event.preventDefault();
      await sendMessage();
      messageInputField.value = "";
    }
  });

  editInputField.addEventListener("keyup", function (event) {
    const editInput = document.querySelector(".edit-input");

    // If the user presses the "Enter" key on the keyboard
    if (event.key === "Enter" && editInputField.value.trim().length > 0) {
      // Cancel the default action, if needed
      event.preventDefault();
      editMessage(editInputField.dataset.messageId, editInputField.value);
      editInputField.dataset.messageId = "";
      editInputField.value = "";
      editInput.style.display = "none";
    } else if (event.key === "Escape") {
      editInput.style.display = "none";
    }
  });
});

getData();

//*==================DOM MANIPULATORS===================

function summonEditInput(content, rect, messageId) {
  const editInputField = document.querySelector(".edit-input-field");
  const editInput = document.querySelector(".edit-input");
  editInputField.value = content;
  editInput.style.display = "block";
  editInput.style.left = `${rect.left}px`;
  editInput.style.top = `${rect.top}px`;
  editInput.style.width = `${rect.width}px`;
  editInput.style.height = `${rect.height}px`;
  editInputField.dataset.messageId = messageId;
}

function updateCurrentChannel(channelId) {
  if (currentChannel !== "") {
    const channel = document.getElementById(currentChannel);
    channel.classList.remove("current-channel");
  }
  const newChannel = document.getElementById(channelId);
  const currentChannelHeader = document.querySelector(
    ".current-channel-header"
  );
  newChannel.classList.add("current-channel");
  currentChannel = channelId;
  currentChannelHeader.textContent = newChannel.textContent;
  renderCurrentChannel();
}

function renderCurrentChannel() {
  if (currentChannel == "") {
    return;
  }
  const messageList = document.querySelector(".messages");

  messageList.textContent = "";

  renderCurrentUsers();
  if (messages[currentChannel] === undefined) {
    messages[currentChannel] = [];
  }
  messages[currentChannel].map((value) => {
    const newDiv = document.createElement("div");
    newDiv.setAttribute("id", value.messageId);
    const usernameDiv = document.createElement("div");
    const msgDiv = document.createElement("div");
    newDiv.classList.add("message-block");
    usernameDiv.classList.add("username");
    msgDiv.classList.add("message");
    usernameDiv.textContent = value.username;
    msgDiv.textContent = value.message;
    newDiv.appendChild(usernameDiv);
    newDiv.appendChild(msgDiv);
    messageList.appendChild(newDiv);
  });
  messageList.scrollTop = messageList.scrollHeight;
}

function renderCurrentUsers() {
  const userList = document.querySelector(".user-list");
  userList.textContent = "";
  users[currentChannel].map((username) => {
    const newUser = document.createElement("li");
    newUser.textContent = username;
    userList.appendChild(newUser);
  });
}

async function renderNewChannel(id, name) {
  const channel = document.createElement("li");
  channel.setAttribute("id", id);
  channel.classList.add("channel");
  channel.textContent = name;
  channel.addEventListener("click", () => {
    updateCurrentChannel(channel.id);
  });
  document.querySelector(".channel-list").appendChild(channel);
}

//*===============SERVER RESPONSE HANDLERS===================

async function handleMessage(channelId, messageId, username, time, encryptedMessage) {
  const message = await decryptMessage(encryptedMessage, keys[channelId]);

  if (channelId === /* currently selected channel */ currentChannel) {
    const newDiv = document.createElement("div");
    newDiv.setAttribute("id", messageId);
    const usernameDiv = document.createElement("div");
    const msgDiv = document.createElement("div");
    newDiv.classList.add("message-block");
    usernameDiv.classList.add("username");
    msgDiv.classList.add("message");
    usernameDiv.textContent = username;
    msgDiv.textContent = message;
    newDiv.appendChild(usernameDiv);
    newDiv.appendChild(msgDiv);
    document.querySelector(".messages").appendChild(newDiv);
  }
  messages[channelId].push({
    messageId: messageId,
    username: username,
    message: message,
  });
}

async function handleEdit(channelId, messageId, encryptedContent) {
  const content = await decryptMessage(encryptedContent, keys[channelId]);

  if (channelId === currentChannel) {
    const editedMessage = document.getElementById(messageId);
    editedMessage.children[1].textContent = content;
  }

  const m = messages[channelId].find((item) => item.messageId === messageId);
  m.message = content;
}

function handleDelete(channelId, messageId) {
  if (channelId === currentChannel) {
    const deletedMessage = document.getElementById(messageId);
    const messageList = document.querySelector(".messages");

    messageList.removeChild(deletedMessage);
  }

  messages[channelId] = messages[channelId].filter(
    (item) => item.messageId !== messageId
  );
}

async function handleSubscribe(channelId, username, encryptedKey) {
  if (channelId === currentChannel) {
    users[channelId].push(username);
    renderCurrentUsers();
  } else {
    keys[channelId] = await decryptChannelKey(encryptedKey);
    const channelData = await fetch(`/api/getChannel/${channelId}`);
    const channelDataJson = await channelData.json();
    messages[channelId] = await Promise.all(
      channelDataJson.messages.map(async (val) => ({
        messageId: val.messageId,
        username: val.username,
        message: await decryptMessage(val.message, keys[channelId]),
      }))
    );
    users[channelId] = channelDataJson.users.map((user) => user.username);
    renderNewChannel(channelId, channelDataJson.name);
  }
}

async function handleCreateChannel(channelId, username, name, encryptedKey) {
  if (encryptedKey) {
    try {
      keys[channelId] = await decryptChannelKey(encryptedKey);
    } catch (err) {
      console.error("Failed to decrypt channel key:", err);
    }
  }
  messages[channelId] = [];
  users[channelId] = [username];
  renderNewChannel(channelId, name);
}

function handleDeleteChannel(channelId) {
  messages[channelId] = [];
  keys[channelId] = [];
  users[channelId] = [];
  const channelLi = document.getElementById(channelId);
  channelLi.parentElement.removeChild(channelLi);
}

//*=================SERVER REQUEST FUNCTIONS==================

async function getData() {
  try {
    const response = await fetch("/api/getData");
    if (response.ok) {
      socket.onclose = () => {
        alert("Connection with the server has been lost. Please login again.");
        document.location.href = "/";
      };
      const result = await response.json();
      // console.log("Success:", result);

      myUsername = result.username;

      for (const channel of result.channels) {
        keys[channel.channelId] = await decryptChannelKey(channel.key);
      }

      for (const channelId of Object.keys(result.messages)) {
        messages[channelId] = await Promise.all(
          result.messages[channelId].map(async (val) => ({
            messageId: val.messageId,
            username: val.username,
            message: await decryptMessage(val.message, keys[channelId]),
          }))
        );
      }
      for (const channelId of Object.keys(result.users)) {
        users[channelId] = result.users[channelId].map((val) => {
          return val.username;
        });
      }

      result.channels.map((value, index) => {
        renderNewChannel(value.channelId, value.channelName);
        if (index === 0) {
          updateCurrentChannel(value.channelId);
        }
      });

      //renderCurrentChannel();
    } else {
      if (response.status === 401) {
        alert("Invalid token, please login again.");
        document.location.href = "/";
      }
      const error = await response.json();
      console.error("Error:", error);
    }
  } catch (error) {
    console.error("Error:", error);
    alert("An error occurred. Please try again.");
  }
}

async function sendMessage() {
  const inputField = document.querySelector(".message-input-field");
  const text = inputField.value;
  if (text !== undefined && text !== "") {
    const encryptedMessage = await encryptMessage(text, keys[currentChannel]);
    // console.log(encryptedMessage);
    socket.send(
      JSON.stringify({ type: "message", arg1: currentChannel, arg2: encryptedMessage })
    );
    inputField.value = "";
  }
}

async function subscribeUser() {
  const inputField = document.querySelector(".subscribe-input-field");
  const username = inputField.value;
  if (username !== undefined && username !== "") {
    try {
      if (currentChannel === "") {
        alert("Please select a channel first.");
        inputField.value = "";
        return;
      }
      const channelKey = await ensureChannelKey(currentChannel);
      const endpoint = "/api/getKey"
      const data = { username }
      const response = await sendData(endpoint, data);
      if (response.ok) {
        const result = await response.json();
        const message = JSON.stringify({
          type: "channelSub",
          arg1: currentChannel,
          arg2: username,
          arg3: await encryptChannelKey(channelKey, result.publicKey)
        })
        socket.send(message);
      } else {
        const error = await response.json();
        console.error("Error:", error);
      }
    } catch (error) {
      console.error("Error:", error);
    }
    inputField.value = "";
  }
}

function createChannel(name, channelKey) {
  socket.send(JSON.stringify({ type: "channelAdd", arg1: name, arg2: channelKey }));
}

function deleteChannel(channelId) {
  socket.send(JSON.stringify({ type: "channelDelete", arg1: channelId }));
}

function deleteMessage(messageId) {
  socket.send(JSON.stringify({ type: "delete", arg1: messageId }));
}
async function editMessage(messageId, newContent) {
  const encryptedContent = await encryptMessage(newContent, keys[currentChannel]);
  socket.send(
    JSON.stringify({ type: "edit", arg1: messageId, arg2: encryptedContent })
  );
}

//*==============MISCELLANEOUS FUNCTIONS================

function getCookie(cname) {
  let name = cname + "=";
  let decodedCookie = decodeURIComponent(document.cookie);
  let ca = decodedCookie.split(";");
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == " ") {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

//*===============CRYPTO FUNCTIONS=======================
async function decryptChannelKey(channelKeyEncrypted) {
  const encryptedBuffer = Uint8Array.from(atob(channelKeyEncrypted), c => c.charCodeAt(0));
  const privateKey = await window.crypto.subtle.importKey(
    "pkcs8",
    str2ab(sessionStorage.getItem("privateKey")),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
  const rawKey = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    encryptedBuffer
  );
  return await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptChannelKey(channelKey, publicKeyBytes) {
  const rawKey = await window.crypto.subtle.exportKey("raw", channelKey);
  const publicKeySpki = normalizePublicKeyInput(publicKeyBytes);
  const publicKey = await window.crypto.subtle.importKey(
    "spki",
    publicKeySpki,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    rawKey
  );

  return bytesToBase64(new Uint8Array(encrypted));
}

async function encryptMessage(message, channelKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(message);

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    channelKey,
    encoded
  );

  return btoa(JSON.stringify({
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  }));
}

async function decryptMessage(encrypted, channelKey) {
  const decoded = JSON.parse(atob(encrypted));
  const iv = base64ToBytes(decoded.iv);
  const ciphertext = base64ToBytes(decoded.ciphertext);

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    channelKey,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

async function generateChannelKey() {
  return window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
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

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) bufView[i] = str.charCodeAt(i);
    return buf;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function isCryptoKey(value) {
  return typeof CryptoKey !== "undefined" && value instanceof CryptoKey;
}

async function ensureChannelKey(channelId) {
  const existing = keys[channelId];
  if (isCryptoKey(existing)) {
    return existing;
  }
  if (typeof existing === "string" && existing !== "") {
    const decrypted = await decryptChannelKey(existing);
    keys[channelId] = decrypted;
    return decrypted;
  }
  const channelData = await fetch(`/api/getChannel/${channelId}`);
  if (!channelData.ok) {
    throw new Error("Failed to fetch channel key");
  }
  const channelDataJson = await channelData.json();
  if (!channelDataJson.key) {
    throw new Error("Missing channel key from server");
  }
  const decrypted = await decryptChannelKey(channelDataJson.key);
  keys[channelId] = decrypted;
  return decrypted;
}

function normalizePublicKeyInput(value) {
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) return value.buffer;
  if (typeof value === "string") {
    if (value.includes("BEGIN PUBLIC KEY")) {
      return pemToArrayBuffer(value);
    }
    try {
      return base64ToBytes(value).buffer;
    } catch (err) {
      return str2ab(value);
    }
  }
  throw new TypeError("Unsupported public key format");
}

function pemToArrayBuffer(pem) {
  const clean = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(clean).buffer;
}
