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
let currentChannel = "";
const token = getCookie("sessionToken");
if (token === "") {
  alert("Invalid token, please login again.");
  document.location.href = "/";
}
console.log(token);
const socket = new WebSocket(`ws://localhost/ws/${token}`);
socket.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.action === "message") {
    if (data.channelId === /* currently selected channel */ currentChannel) {
      const newDiv = document.createElement("div");
      newDiv.setAttribute("id", data.arg1);
      const usernameDiv = document.createElement("div");
      const msgDiv = document.createElement("div");
      const strongElt = document.createElement("strong");
      strongElt.appendChild(document.createTextNode(data.arg2));
      usernameDiv.appendChild(strongElt);
      msgDiv.appendChild(document.createTextNode(data.arg4));
      newDiv.appendChild(usernameDiv);
      newDiv.appendChild(msgDiv);
      document.getElementById("messages").appendChild(newDiv);
    }
  }
};

async function getData() {
  try {
    const response = await fetch("/api/getData", {
      method: "GET",
    });
    if (response.ok) {
      const result = await response.json();
      console.log("Success:", result);

      // handle case where there are no channels
      result.channels.map((value, index) => {
        const newDiv = document.createElement("div");
        newDiv.setAttribute("id", value.channelId);
        const textNode = document.createTextNode(value.channelName);
        if (index === 0) {
          currentChannel = value.channelId;
          const strongElt = document.createElement("strong");
          strongElt.appendChild(textNode);
          newDiv.appendChild(strongElt);
        } else {
          newDiv.appendChild(textNode);
        }
        document.getElementById("channel-list").appendChild(newDiv);
      });
      result.messages[currentChannel].map((value) => {
        const newDiv = document.createElement("div");
        newDiv.setAttribute("id", value.messageId);
        const usernameDiv = document.createElement("div");
        const msgDiv = document.createElement("div");
        const strongElt = document.createElement("strong");
        strongElt.appendChild(document.createTextNode(value.username));
        usernameDiv.appendChild(strongElt);
        msgDiv.appendChild(document.createTextNode(value.message));
        newDiv.appendChild(usernameDiv);
        newDiv.appendChild(msgDiv);
        document.getElementById("messages").appendChild(newDiv);
      });
      result.users[currentChannel].map((value) => {
        const newDiv = document.createElement("div");
        newDiv.setAttribute("id", value.userId);
        const strongElt = document.createElement("strong");
        strongElt.appendChild(document.createTextNode(value.username));
        newDiv.appendChild(strongElt);
        document.getElementById("user-list").appendChild(newDiv);
      });
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

getData();

function sendMessage() {
  const inputField = document.getElementById("message-input-field");
  const text = inputField.value;
  if (text !== undefined && text !== "") {
    socket.send(
      JSON.stringify({ type: "message", arg1: currentChannel, arg2: text })
    );
    inputField.value = "";
  }
}
