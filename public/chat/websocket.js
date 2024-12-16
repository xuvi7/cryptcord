let messages = {}; //* dict of channelId to array of {messageId, username, message}
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
socket.onmessage = (event) => {
  const data = JSON.parse(event.data);
  switch (data.action) {
    case "message":
      handleMessage(data.channelId, data.arg1, data.arg2, data.arg3, data.arg4);
      break;
    case "edit":
      handleEdit(data.channelId, data.arg1, data.arg2);
      break;
    case "delete":
      handleDelete(data.channelId, data.arg1);
      break;
    case "subscribe":
      handleSubscribe(data.channelId, data.arg1);
      break;
    case "createChannel":
      handleCreateChannel(data.channelId, data.arg1, data.arg2);
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
  createChannelForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const newChannelName = newChannelInput.value.trim();
    if (newChannelName) {
      createChannel(newChannelName);
      newChannelInput.value = "";
    }
  });

  // Context menu for channels
  channelList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const clickedChannel = e.target.closest("li");
    if (clickedChannel && clickedChannel.id !== currentChannel) {
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
    const clickedMessage = e.target.closest(".message-block");
    if (clickedMessage === null) {
      return;
    }
    const username = clickedMessage.firstElementChild;
    const message = clickedMessage.lastElementChild;
    const messageRect = message.getBoundingClientRect();
    if (username && username.textContent === myUsername) {
      messageContextMenu.style.display = "block";
      messageContextMenu.style.left = `${e.pageX}px`;
      messageContextMenu.style.top = `${e.pageY}px`;
      editMessageOption.onclick = () => {
        summonEditInput(message.textContent, messageRect, clickedMessage.id);
      };
      deleteMessageOption.onclick = () => {
        deleteMessage(clickedMessage.id);
      };
    }
  });

  // Hide context menu when clicking outside
  document.addEventListener("click", () => {
    channelContextMenu.style.display = "none";
    messageContextMenu.style.display = "none";
  });

  messageInputField.addEventListener("keypress", function (event) {
    // If the user presses the "Enter" key on the keyboard
    if (event.key === "Enter") {
      // Cancel the default action, if needed
      event.preventDefault();
      sendMessage();
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
    const newUser = document.createElement("div");
    newUser.textContent = username;
    userList.appendChild(newUser);
  });
}

async function renderNewChannel(id, name) {
  const channel = document.createElement("li");
  channel.setAttribute("id", id);
  channel.textContent = name;
  channel.addEventListener("click", () => {
    updateCurrentChannel(channel.id);
  });
  document.querySelector(".channel-list").appendChild(channel);
}

//*===============SERVER RESPONSE HANDLERS===================

function handleMessage(channelId, messageId, username, time, message) {
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

function handleEdit(channelId, messageId, content) {
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

async function handleSubscribe(channelId, username) {
  if (channelId === currentChannel) {
    users[channelId].push(username);
    renderCurrentUsers();
  } else {
    const channelData = await fetch(`/api/getChannel/${channelId}`);
    const channelDataJson = await channelData.json();
    messages[channelId] = channelDataJson.messages;
    users[channelId] = channelDataJson.users.map((user) => user.username);
    renderNewChannel(channelId, channelDataJson.name);
  }
}

function handleCreateChannel(channelId, username, name) {
  messages[channelId] = [];
  users[channelId] = [username];
  renderNewChannel(channelId, name);
}

function handleDeleteChannel(channelId) {
  messages[channelId] = [];
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

      for (const channel in result.messages) {
        messages[channel] = result.messages[channel];
        //result.messages[channel].map((val) => {
        /*messages[channel].push({
            messageId: val.messageId,
            username: val.username,
            message: val.message,
          });*/
        //});
      }
      for (const channel in result.users) {
        users[channel] = result.users[channel].map((val) => {
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

function sendMessage() {
  const inputField = document.querySelector(".message-input-field");
  const text = inputField.value;
  if (text !== undefined && text !== "") {
    socket.send(
      JSON.stringify({ type: "message", arg1: currentChannel, arg2: text })
    );
    inputField.value = "";
  }
}

function subscribeUser() {
  const inputField = document.querySelector(".subscribe-input-field");
  const username = inputField.value;
  if (username !== undefined && username !== "") {
    socket.send(
      JSON.stringify({
        type: "channelSub",
        arg1: currentChannel,
        arg2: username,
      })
    );
    inputField.value = "";
  }
}

function createChannel(name) {
  socket.send(JSON.stringify({ type: "channelAdd", arg1: name }));
}

function deleteChannel(channelId) {
  socket.send(JSON.stringify({ type: "channelDelete", arg1: channelId }));
}

function deleteMessage(messageId) {
  socket.send(JSON.stringify({ type: "delete", arg1: messageId }));
}
function editMessage(messageId, newContent) {
  socket.send(
    JSON.stringify({ type: "edit", arg1: messageId, arg2: newContent })
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
