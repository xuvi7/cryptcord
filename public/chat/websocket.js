let messages = {}
let users = {}
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
    case "edit":
      handleEdit(data.channelId, data.arg1, data.arg2);
    case "delete":
      handleDelete(data.channelId, data.arg1);
    case "subscribe":
      handleSubscribe(data.channelId, data.arg1);
    case "createChannel":
      handleCreateChannel(data.channelId, data.arg1, data.arg2);
    case "deleteChannel":
      handleDeleteChannel(data.channelId);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const channelList = document.querySelector('.channel-list');
  const createChannelForm = document.querySelector('.create-channel-form');
  const newChannelInput = document.querySelector('.new-channel-input');
  const contextMenu = document.querySelector('.context-menu');
  const deleteChannelOption = document.querySelector('.delete-channel');

  // Create new channel
  createChannelForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const newChannelName = newChannelInput.value.trim();
    if (newChannelName) {
      createChannel(newChannelName)
      newChannelInput.value = '';
    }
  });

  // Context menu for channels
  channelList.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    const clickedChannel = e.target.closest('li');
    if (clickedChannel) {
      contextMenu.style.display = 'block';
      contextMenu.style.left = `${e.pageX}px`;
      contextMenu.style.top = `${e.pageY}px`;
      deleteChannelOption.onclick = () => {
        deleteChannel();
      };
    }
  });

  // Hide context menu when clicking outside
  document.addEventListener('click', () => {
    contextMenu.style.display = 'none';
  });
});

getData();

//*==================DOM MANIPULATORS===================

function updateCurrentChannel(channelId) {
  if (currentChannel !== "") {
    const channel = document.getElementById(currentChannel);
    channel.classList.remove("current-channel")
  }
  const newChannel = document.getElementById(channelId);
  const currentChannelHeader = document.querySelector(".current-channel-header")
  newChannel.classList.add("current-channel")
  currentChannel = channelId;
  currentChannelHeader.textContent = newChannel.textContent;
  renderCurrentChannel()
}

function renderCurrentChannel() {
  if (currentChannel == "") {
    return;
  }
  const messageList = document.querySelector(".messages");
  const userList = document.querySelector(".user-list");

  messageList.textContent = '';
  userList.textContent = '';

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
  users[currentChannel].map((value) => {
    const newDiv = document.createElement("div");
    newDiv.setAttribute("id", value.userId);
    newDiv.textContent = value.username;
    userList.appendChild(newDiv);
  });
}

function renderNewChannel(id, name) {
  messages[id] = []
  users[id] = []
  const channel = document.createElement("li");
  channel.setAttribute("id", id);
  channel.textContent = name;
  channel.addEventListener('click', () => {
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
  messages[channelId].push({ "messageId": messageId, "username": username, "message": message })
}

function handleEdit(channelId, messageId, content) {

}

function handleDelete(channelId, messageId) {

}

function handleSubscribe(channelId, username) {

}

function handleCreateChannel(channelId, username, name) {
  // TODO: need to handle users
  // TODO: figure out ordering problem
  renderNewChannel(channelId, name)
}

function handleDeleteChannel(channelId) {

}

//*=================SERVER REQUEST FUNCTIONS==================

async function getData() {
  try {
    const response = await fetch("/api/getData", {
      method: "GET",
    });
    if (response.ok) {
      const result = await response.json();
      // console.log("Success:", result);

      // handle case where there are no channels
      result.channels.map((value, index) => {
        renderNewChannel(value.channelId, value.channelName)
        if (index === 0) {
          updateCurrentChannel(value.channelId);
        }
      });
      for (const channel in result.messages) {
        result.messages[channel].map((val) => {
          messages[channel].push({ "messageId": val.messageId, "username": val.username, "message": val.message })
        });
      }
      for (const channel in result.users) {
        result.users[channel].map((val) => {
          users[channel].push({ "userId": val.userId, "username": val.username })
        });
      }

      renderCurrentChannel()
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

function createChannel(name) {
  socket.send(
    JSON.stringify({ type: "channelAdd", arg1: name })
  );
}

function deleteChannel(channelId) {
  socket.send(
    JSON.stringify({ type: "channelDelete", arg1: channelId })
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