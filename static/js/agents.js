document.addEventListener('DOMContentLoaded', function() {
    const addAgentBtn = document.getElementById('add-agent-btn');
    const addAgentModal = document.getElementById('add-agent-modal');
    const addAgentForm = document.getElementById('add-agent-form');
    const selectedAgentName = document.getElementById('selected-agent-name');
    const agentsTable = document.getElementById('agents-table');
    const closeBtn = addAgentModal.querySelector('.close');

    addAgentBtn.addEventListener('click', () => toggleModal(addAgentModal, true));
    closeBtn.addEventListener('click', () => toggleModal(addAgentModal, false));
    addAgentForm.addEventListener('submit', handleAddAgent);
    agentsTable.addEventListener('click', handleTableActions);

    window.onclick = (event) => {
        if (event.target == addAgentModal) {
            toggleModal(addAgentModal, false);
        }
    };

    fetchSelectedAgent();
    initializeTooltips();
});

function handleAddAgent(e) {
    e.preventDefault();
    const name = document.getElementById('agent-name').value;
    const ipAddress = document.getElementById('agent-ip').value;
    addAgent(name, ipAddress);
}

function handleTableActions(e) {
    const target = e.target;
    if (target.tagName === 'BUTTON') {
        const action = target.dataset.action;
        const agentId = target.dataset.agentId;
        switch (action) {
            case 'remove':
                removeAgent(agentId);
                break;
            case 'check-status':
                checkAgentStatus(agentId);
                break;
            case 'select':
                selectAgent(agentId);
                break;
        }
    }
}

function addAgent(name, ipAddress) {
    fetch('/api/agents', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, ip_address: ipAddress }),
    })
    .then(handleResponse)
    .then(data => {
        showNotification(data.message, 'success');
        location.reload();
    })
    .catch(error => showError('Error adding agent:', error));
}

function removeAgent(agentId) {
    if (confirm('Are you sure you want to remove this agent?')) {
        fetch(`/api/agents?id=${agentId}`, { method: 'DELETE' })
        .then(handleResponse)
        .then(data => {
            showNotification(data.message, 'success');
            location.reload();
        })
        .catch(error => showError('Error removing agent:', error));
    }
}

function checkAgentStatus(agentId) {
    fetch(`/api/check_agent_status/${agentId}`)
    .then(handleResponse)
    .then(data => {
        const statusCell = document.querySelector(`.agent-status[data-agent-id="${agentId}"]`);
        if (statusCell) {
            statusCell.textContent = data.status;
            statusCell.classList.add('status-updated');
            setTimeout(() => statusCell.classList.remove('status-updated'), 3000);
        }
        showNotification(`Agent status updated: ${data.status}`, 'info');
    })
    .catch(error => showError('Error checking agent status:', error));
}

function selectAgent(agentId) {
    fetch(`/select_agent/${agentId}`, { method: 'POST' })
    .then(handleResponse)
    .then(data => {
        showNotification('Agent selected successfully', 'success');
        fetchSelectedAgent();
    })
    .catch(error => showError('Error selecting agent:', error));
}

function fetchSelectedAgent() {
    fetch('/api/selected_agent')
    .then(handleResponse)
    .then(data => {
        const selectedAgentName = document.getElementById('selected-agent-name');
        selectedAgentName.textContent = data.selected_agent ? data.selected_agent.name : 'None';
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('selected-agent-name').textContent = 'Error fetching selected agent';
    });
}

function handleResponse(response) {
    if (!response.ok) {
        return response.json().then(err => { throw err; });
    }
    return response.json();
}

function showError(message, error) {
    console.error(message, error);
    showNotification(`${message} ${error.message || 'Unknown error'}`, 'error');
}

function showNotification(message, type) {
    // Implement a notification system (e.g., toast notifications)
    alert(`${type.toUpperCase()}: ${message}`);
}

function toggleModal(modal, show) {
    modal.style.display = show ? 'block' : 'none';
}

function initializeTooltips() {
    // Implement tooltips for buttons
    // This is a placeholder for potential tooltip functionality
}