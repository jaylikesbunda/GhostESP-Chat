// GhostESP: Chat - Web UI JavaScript
// A spin-off of GhostESP: Revival firmware

let ws = null;
let reconnectTimer = null;
let deviceInfo = {};
let peers = [];
let currentPeer = null;
let messages = {};
let receivedMessageIds = new Set();  // Track received message IDs for deduplication

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Load received message IDs from localStorage for deduplication across page reloads
    try {
        const storedIds = localStorage.getItem('receivedMessageIds');
        if (storedIds) {
            receivedMessageIds = new Set(JSON.parse(storedIds));
        }
    } catch (e) {
        console.warn('Failed to load message IDs from localStorage:', e);
    }

    loadDeviceInfo();
    loadPeers();
    connectWebSocket();

    // Attach event listeners
    const addPeerBtn = document.querySelector('.add-peer-btn');
    if (addPeerBtn) {
        addPeerBtn.addEventListener('click', showAddPeerModal);
    } else {
        console.error('Could not find add peer button!');
    }

    const addPeerForm = document.getElementById('addPeerForm');
    if (addPeerForm) {
        addPeerForm.addEventListener('submit', addPeer);
    }

    const cancelPeerBtn = document.getElementById('cancelPeerBtn');
    if (cancelPeerBtn) {
        cancelPeerBtn.addEventListener('click', hideAddPeerModal);
    }

    // Close modal when clicking outside
    const modal = document.getElementById('addPeerModal');
    if (modal) {
        modal.addEventListener('click', (event) => {
            if (event.target.id === 'addPeerModal') {
                hideAddPeerModal();
            }
        });
    }

    const chatForm = document.getElementById('chatForm');
    if (chatForm) {
        chatForm.addEventListener('submit', sendMessage);
    }


    // Copy public key button
    const copyPubKeyBtn = document.getElementById('copyPubKey');
    if (copyPubKeyBtn) {
        copyPubKeyBtn.addEventListener('click', copyPublicKey);
    }

    // Mobile sidebar toggle
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const sidebarCloseBtn = document.getElementById('sidebarCloseBtn');

    function openSidebar() {
        sidebar.classList.add('show');
        sidebarOverlay.classList.add('show');
    }

    function closeSidebar() {
        sidebar.classList.remove('show');
        sidebarOverlay.classList.remove('show');
    }

    if (mobileMenuBtn) mobileMenuBtn.addEventListener('click', openSidebar);
    if (sidebarCloseBtn) sidebarCloseBtn.addEventListener('click', closeSidebar);
    if (sidebarOverlay) sidebarOverlay.addEventListener('click', closeSidebar);
});

/**
 * Load device information from API
 */
async function loadDeviceInfo() {
    try {
        const response = await fetch('/api/info');
        deviceInfo = await response.json();

        document.getElementById('localIp').textContent = deviceInfo.local_ip;
        document.getElementById('publicIp').textContent = deviceInfo.public_ip || 'Unknown';
        document.getElementById('port').textContent = deviceInfo.port;

        // Display public key (truncate if too long)
        if (deviceInfo.public_key) {
            const pubKeyElement = document.getElementById('publicKey');
            pubKeyElement.textContent = deviceInfo.public_key;
            pubKeyElement.title = deviceInfo.public_key;
        }

        // UPnP / NAT status
        const upnpEl = document.getElementById('upnpStatus');
        const natEl = document.getElementById('natStatus');
        const extEl = document.getElementById('externalAddr');

        if (upnpEl) {
            upnpEl.textContent = deviceInfo.upnp_available ? 'Available' : 'Not found';
            upnpEl.style.color = deviceInfo.upnp_available ? '#10b981' : 'var(--text-secondary)';
        }
        if (natEl) {
            if (deviceInfo.port_mapped) {
                natEl.textContent = 'Port ' + deviceInfo.mapped_port + ' mapped';
                natEl.style.color = '#10b981';
            } else if (deviceInfo.upnp_available) {
                natEl.textContent = 'Mapping failed';
                natEl.style.color = '#f59e0b';
            } else {
                natEl.textContent = 'Manual forwarding needed';
                natEl.style.color = '#ef4444';
            }
        }
        if (extEl) {
            const addr = deviceInfo.external_address;
            if (addr && addr !== 'Not available') {
                extEl.textContent = addr;
                extEl.style.color = '#10b981';
            } else {
                extEl.textContent = 'Not reachable';
                extEl.style.color = 'var(--text-secondary)';
            }
        }

    } catch (error) {
        console.error('Failed to load device info:', error);
    }
}

/**
 * Load peer list from API
 */
async function loadPeers() {
    try {
        const response = await fetch('/api/peers');
        peers = await response.json();

        renderPeerList();
    } catch (error) {
        console.error('Failed to load peers:', error);
    }
}

/**
 * Clear chat history for a peer
 */
async function clearChatHistory(peerId) {
    const peer = peers.find(p => p.id === peerId);
    if (!peer) return;

    if (!confirm(`Clear all chat history with ${peer.name}?`)) return;

    try {
        const response = await fetch(`/api/chat/delete?peer=${encodeURIComponent(peer.ip)}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            // Clear from local memory
            messages[peerId] = [];
            renderMessages();
        } else {
            alert('Failed to clear chat history');
        }
    } catch (error) {
        console.error('Failed to clear chat history:', error);
        alert('Error clearing chat history');
    }
}

/**
 * Render peer list in sidebar
 */
function renderPeerList() {
    const peerList = document.getElementById('peerList');

    if (peers.length === 0) {
        peerList.innerHTML = '<div style="text-align:center; color:#9ca3af; padding:20px;">No peers yet.<br>Add one to start chatting!</div>';
        return;
    }

    peerList.innerHTML = peers.map(peer => `
        <div class="peer-item ${currentPeer && currentPeer.id === peer.id ? 'active' : ''}"
             data-peer-id="${peer.id}">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div class="peer-name">
                    <div class="${peer.online ? 'online-badge' : 'offline-badge'}"></div>
                    ${escapeHtml(peer.name)}
                </div>
                <div style="display:flex;gap:4px">
                    <button class="clear-history-btn" data-peer-id="${peer.id}" title="Clear chat history" style="background:none;border:none;color:#f59e0b;cursor:pointer;font-size:0.8rem;padding:2px 6px;opacity:0.5;transition:opacity 0.2s">🗑</button>
                    <button class="delete-peer-btn" data-peer-id="${peer.id}" title="Remove peer" style="background:none;border:none;color:#ef4444;cursor:pointer;font-size:0.9rem;padding:2px 6px;opacity:0.5;transition:opacity 0.2s">&times;</button>
                </div>
            </div>
            <div class="peer-status">${peer.ip}:${peer.port}</div>
        </div>
    `).join('');

    peerList.querySelectorAll('.peer-item').forEach(item => {
        item.addEventListener('click', (e) => {
            if (e.target.classList.contains('delete-peer-btn') ||
                e.target.classList.contains('clear-history-btn')) return;
            const peerId = item.getAttribute('data-peer-id');
            selectPeer(peerId);
        });
    });

    peerList.querySelectorAll('.clear-history-btn').forEach(btn => {
        btn.addEventListener('mouseenter', () => btn.style.opacity = '1');
        btn.addEventListener('mouseleave', () => btn.style.opacity = '0.5');
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            clearChatHistory(btn.getAttribute('data-peer-id'));
        });
    });

    peerList.querySelectorAll('.delete-peer-btn').forEach(btn => {
        btn.addEventListener('mouseenter', () => btn.style.opacity = '1');
        btn.addEventListener('mouseleave', () => btn.style.opacity = '0.5');
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            deletePeer(btn.getAttribute('data-peer-id'));
        });
    });
}

/**
 * Load chat history from persistent storage
 */
async function loadChatHistory(peerIp) {
    try {
        const response = await fetch(`/api/chat/history?peer=${encodeURIComponent(peerIp)}`);
        if (!response.ok) {
            console.warn('Failed to load chat history for', peerIp);
            return [];
        }

        const data = await response.json();

        // Convert backend format to frontend format
        return data.messages.map(msg => ({
            sender: msg.direction === 'sent' ? 'You' : (currentPeer ? currentPeer.name : 'Unknown'),
            text: msg.message,
            timestamp: msg.timestamp * 1000, // Backend uses seconds, frontend uses milliseconds
            sent: msg.direction === 'sent'
        }));
    } catch (error) {
        console.error('Error loading chat history:', error);
        return [];
    }
}

/**
 * Select a peer to chat with
 */
async function selectPeer(peerId) {
    currentPeer = peers.find(p => p.id === peerId);

    if (!currentPeer) return;

    document.getElementById('chatTitle').textContent = `Chat with ${currentPeer.name}`;

    // Initialize message array if needed and load history
    if (!messages[peerId]) {
        messages[peerId] = [];
    }

    // Load persisted chat history from backend
    if (currentPeer.ip) {
        const history = await loadChatHistory(currentPeer.ip);
        if (history.length > 0) {
            // Merge with any existing messages (avoid duplicates)
            const existingTexts = new Set(messages[peerId].map(m => m.text + m.timestamp));
            const newMessages = history.filter(msg =>
                !existingTexts.has(msg.text + msg.timestamp)
            );
            messages[peerId] = [...history, ...messages[peerId].filter(m =>
                !history.some(h => h.text === m.text && h.timestamp === m.timestamp)
            )];
            // Sort by timestamp
            messages[peerId].sort((a, b) => a.timestamp - b.timestamp);
        }
    }

    renderMessages();
    renderPeerList();

    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    if (sidebar) sidebar.classList.remove('show');
    if (sidebarOverlay) sidebarOverlay.classList.remove('show');
}

/**
 * Render messages in chat area
 */
function renderMessages() {
    const chatMessages = document.getElementById('chatMessages');

    if (!currentPeer) {
        chatMessages.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">Chat</div>
                <h3>No conversation selected</h3>
                <p>Choose a peer from the sidebar or add a new one to start chatting</p>
            </div>
        `;
        return;
    }

    const peerMessages = messages[currentPeer.id] || [];

    if (peerMessages.length === 0) {
        chatMessages.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">Start</div>
                <h3>Start your conversation</h3>
                <p>Send your first encrypted message to ${escapeHtml(currentPeer.name)}</p>
            </div>
        `;
        return;
    }

    chatMessages.innerHTML = peerMessages.map(msg => `
        <div class="message ${msg.sent ? 'sent' : 'received'}">
            <div class="message-bubble">
                <div class="message-sender">${escapeHtml(msg.sender)}</div>
                <div class="message-text">${escapeHtml(msg.text)}</div>
                <div class="message-time">${formatTime(msg.timestamp)}</div>
            </div>
        </div>
    `).join('');

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Send a message
 */
async function sendMessage(event) {
    event.preventDefault();

    const input = document.getElementById('messageInput');
    const text = input.value.trim();

    if (!text || !currentPeer) return;

    const message = {
        type: 1, // WS_MSG_CHAT
        data: {
            peer_id: currentPeer.id,
            text: text
        }
    };

    // Send via WebSocket
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));

        // Add to local messages
        if (!messages[currentPeer.id]) {
            messages[currentPeer.id] = [];
        }

        messages[currentPeer.id].push({
            sender: 'You',
            text: text,
            timestamp: Date.now(),
            sent: true
        });

        renderMessages();
        input.value = '';
    } else {
        alert('WebSocket not connected. Please wait...');
    }
}

/**
 * Connect to WebSocket
 */
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        updateStatus(true);

        // Clear reconnect timer
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWebSocketMessage(msg);
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateStatus(false);
    };

    ws.onclose = () => {
        updateStatus(false);

        // Reconnect after 3 seconds
        if (!reconnectTimer) {
            reconnectTimer = setTimeout(() => {
                connectWebSocket();
            }, 3000);
        }
    };
}

/**
 * Handle incoming WebSocket message
 */
function handleWebSocketMessage(msg) {
    switch (msg.type) {
        case 1: // WS_MSG_CHAT
            handleChatMessage(msg.data);
            break;

        case 2: // WS_MSG_STATUS
            handleStatusUpdate(msg.data);
            break;

        case 3: // WS_MSG_PEER_LIST
            handlePeerListUpdate(msg.data);
            break;

        case 4: // WS_MSG_SYSTEM
            handleSystemMessage(msg.data);
            break;

        case 5: // WS_MSG_ERROR
            handleErrorMessage(msg.data);
            break;

        default:
            console.warn('Unknown message type:', msg.type);
    }
}

/**
 * Handle incoming chat message
 */
function handleChatMessage(data) {
    // Generate message ID for deduplication
    // Use server-provided msg_id if available, otherwise create hash
    let msgId = data.msg_id;
    if (!msgId) {
        // Fallback: create hash from content for older messages without msg_id
        msgId = `${data.peer_id}-${data.timestamp || Date.now()}-${data.text.substring(0, 50)}`;
    }

    // Check if we've already received this message
    if (receivedMessageIds.has(msgId)) {
        return;
    }

    // Mark message as received
    receivedMessageIds.add(msgId);

    // Clean up old message IDs (keep last 1000)
    if (receivedMessageIds.size > 1000) {
        const idsArray = Array.from(receivedMessageIds);
        receivedMessageIds = new Set(idsArray.slice(-1000));
    }

    // Persist to localStorage for cross-tab/reload deduplication
    try {
        localStorage.setItem('receivedMessageIds', JSON.stringify(Array.from(receivedMessageIds)));
    } catch (e) {
        console.warn('Failed to save message IDs to localStorage:', e);
    }

    const peerId = data.peer_id;

    if (!messages[peerId]) {
        messages[peerId] = [];
    }

    messages[peerId].push({
        sender: data.sender || 'Unknown',
        text: data.text,
        timestamp: data.timestamp || Date.now(),
        sent: false,
        msg_id: msgId
    });

    // Update UI if viewing this peer
    if (currentPeer && currentPeer.id === peerId) {
        renderMessages();
    }
    // Note: Visual/audio notifications for messages from non-active peers could be added here
}

/**
 * Handle peer status update
 */
function handleStatusUpdate(data) {
    const peer = peers.find(p => p.id === data.peer_id);

    if (peer) {
        peer.online = data.online;
        renderPeerList();
    }
}

/**
 * Handle peer list update
 */
function handlePeerListUpdate(data) {
    if (Array.isArray(data)) {
        peers = data;
        renderPeerList();
    }
}

/**
 * Handle system message
 */
function handleSystemMessage(data) {
    // System message received - currently no action taken
}

/**
 * Handle error message
 */
function handleErrorMessage(data) {
    console.error('Error message:', data);
    alert('Error: ' + (data.message || 'Unknown error'));
}

/**
 * Update connection status indicator
 */
function updateStatus(connected) {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    if (connected) {
        statusDot.classList.remove('offline');
        statusText.textContent = 'Connected';
    } else {
        statusDot.classList.add('offline');
        statusText.textContent = 'Disconnected';
    }
}

/**
 * Show add peer modal
 */
function showAddPeerModal(event) {
    const modal = document.getElementById('addPeerModal');
    if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('show');
    } else {
        console.error('Could not find modal element!');
    }

    // Prevent default form submission if this was triggered by a form
    if (event) {
        event.preventDefault();
    }
}

/**
 * Hide add peer modal
 */
function hideAddPeerModal() {
    const modal = document.getElementById('addPeerModal');
    if (modal) {
        modal.classList.remove('show');
        modal.style.display = 'none';
    }
    const form = document.getElementById('addPeerForm');
    if (form) {
        form.reset();
    }
}

/**
 * Add a new peer
 */
async function addPeer(event) {
    event.preventDefault();

    const name = document.getElementById('peerName').value.trim();
    const ip = document.getElementById('peerIp').value.trim();
    const port = parseInt(document.getElementById('peerPort').value);
    const pubkey = document.getElementById('peerPubkey').value.trim();

    if (!name || !ip || !port || !pubkey) {
        alert('Please fill in all fields');
        return;
    }

    const peerData = {
        name: name,
        ip: ip,
        port: port,
        public_key: pubkey
    };

    try {
        const response = await fetch('/api/peer/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(peerData)
        });

        if (response.ok) {
            hideAddPeerModal();
            loadPeers();
        } else {
            const error = await response.text();
            alert('Failed to add peer: ' + error);
        }
    } catch (error) {
        console.error('Failed to add peer:', error);
        alert('Failed to add peer: ' + error.message);
    }
}

async function deletePeer(peerId) {
    if (!confirm('Remove this peer?')) return;
    try {
        const response = await fetch('/api/peer/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ peer_id: peerId })
        });
        if (response.ok) {
            if (currentPeer && currentPeer.id === peerId) {
                currentPeer = null;
                document.getElementById('chatTitle').textContent = 'Select a peer to start chatting';
                renderMessages();
            }
            delete messages[peerId];
            loadPeers();
        } else {
            alert('Failed to remove peer');
        }
    } catch (error) {
        console.error('Failed to delete peer:', error);
    }
}

/**
 * Format timestamp
 */
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();

    const isToday = date.toDateString() === now.toDateString();

    if (isToday) {
        return date.toLocaleTimeString('en-US', {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    } else {
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Copy public key to clipboard
 */
async function copyPublicKey() {
    const pubKeyElement = document.getElementById('publicKey');
    const copyBtn = document.getElementById('copyPubKey');

    if (!pubKeyElement || !deviceInfo.public_key) {
        alert('Public key not available');
        return;
    }

    try {
        // Use modern Clipboard API if available
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(deviceInfo.public_key);
        } else {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = deviceInfo.public_key;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }

        // Visual feedback
        const originalText = copyBtn.textContent;
        copyBtn.textContent = 'Copied';
        copyBtn.style.color = '#10b981';

        setTimeout(() => {
            copyBtn.textContent = originalText;
            copyBtn.style.color = '';
        }, 2000);
    } catch (error) {
        console.error('Failed to copy public key:', error);
        alert('Failed to copy to clipboard. Please copy manually.');
    }
}
