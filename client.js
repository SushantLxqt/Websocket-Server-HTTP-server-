let socket = null;
let myRole = null;
let bothClientsReady = false;

function connect() {
    if (socket && (
        socket.readyState === WebSocket.OPEN ||
        socket.readyState === WebSocket.CONNECTING
    )) {
        setStatus(bothClientsReady ? "Both clients ready" : "Waiting for the other client");
        return;
    }

    myRole = null;
    bothClientsReady = false;
    updateChatControls();
    setStatus("Connecting...");

    socket = new WebSocket("ws://localhost:8080");

    socket.onopen = function () {
        setStatus("Connected — waiting for the other client");
        updateChatControls();
    };

    socket.onmessage = function (event) {
        const data = String(event.data);

        // System messages control the UI and must never be shown as chat messages.
        if (data.startsWith("SYS:")) {
            const parts = data.split(":");
            const command = parts[1];

            if (command === "ROLE") {
                myRole = parts[2];
            } else if (command === "WAITING") {
                bothClientsReady = false;
                setStatus("Waiting for the other client");
            } else if (command === "READY") {
                bothClientsReady = true;
                setStatus("Both clients ready — you can chat");
            } else if (command === "PEER_LEFT") {
                bothClientsReady = false;
                setStatus("Other client disconnected — waiting for them to reconnect");
                addMessage("System: The other client disconnected. Chat is paused until they reconnect.");
            }

            updateChatControls();
            return;
        }

        // Only show chat messages once the server says both clients are ready.
        if (!bothClientsReady) {
            return;
        }

        const peerLabel = myRole === "A" ? "Client B" : "Client A";
        addMessage(peerLabel + ": " + data);
    };

    socket.onclose = function () {
        bothClientsReady = false;
        setStatus("Disconnected");
        addMessage("System: Connection closed.");
        updateChatControls();
    };

    socket.onerror = function () {
        setStatus("Connection error");
        addMessage("System: WebSocket error. Check that the C server is running on port 8080.");
    };
}

function sendMessage() {
    const input = document.getElementById("messageInput");
    const message = input.value.trim();

    if (message === "") return;

    if (!socket || socket.readyState !== WebSocket.OPEN) {
        addMessage("System: Connect to the server first.");
        return;
    }

    if (!bothClientsReady) {
        setStatus("Waiting for the other client");
        return;
    }

    socket.send(message);
    addMessage("You: " + message);
    input.value = "";
    input.focus();
}

function addMessage(message) {
    const messages = document.getElementById("messages");
    const line = document.createElement("p");
    line.textContent = message;
    messages.appendChild(line);
    messages.scrollTop = messages.scrollHeight;
}

function clearMessage() {
    document.getElementById("messages").replaceChildren();
}

function setStatus(message) {
    document.getElementById("status").textContent = message;
}

function updateChatControls() {
    const canSend = Boolean(
        socket && socket.readyState === WebSocket.OPEN && bothClientsReady
    );
    document.getElementById("messageInput").disabled = !canSend;
    document.getElementById("sendButton").disabled = !canSend;
    document.getElementById("messageInput").placeholder = canSend
        ? "Type a message..."
        : "Waiting for both clients to connect...";
}

document.addEventListener("DOMContentLoaded", function () {
    updateChatControls();
    document.getElementById("messageInput").addEventListener("keydown", function (event) {
        if (event.key === "Enter") sendMessage();
    });
});
