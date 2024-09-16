document.addEventListener('DOMContentLoaded', function() {
    const addAgentBtn = document.getElementById('add-agent-btn');
    const addAgentModal = document.getElementById('add-agent-modal');
    const addAgentForm = document.getElementById('add-agent-form');
    const selectedAgentName = document.getElementById('selected-agent-name');

    addAgentBtn.addEventListener('click', () => {
        addAgentModal.style.display = 'block';
    });

    addAgentForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const name = document.getElementById('agent-name').value;
        const ipAddress = document.getElementById('agent-ip').value;
        addAgent(name, ipAddress);
    });

    window.onclick = (event) => {
        if (event.target == addAgentModal) {
            addAgentModal.style.display = 'none';
        }
    };

    fetchSelectedAgent();
});

function addAgent(name, ipAddress) {
    fetch('/api/agents', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, ip_address: ipAddress }),
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        location.reload();
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error adding agent');
    });
}

function removeAgent(agentId) {
    if (confirm('Are you sure you want to remove this agent?')) {
        fetch(`/api/agents?id=${agentId}`, {
            method: 'DELETE',
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            location.reload();
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('Error removing agent');
        });
    }
}

function checkAgentStatus(agentId) {
    fetch(`/api/check_agent_status/${agentId}`)
    .then(response => response.json())
    .then(data => {
        alert(`Agent status: ${data.status}`);
        location.reload();
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error checking agent status');
    });
}

function selectAgent(agentId) {
    fetch(`/select_agent/${agentId}`)
    .then(response => {
        if (response.ok) {
            alert('Agent selected successfully');
            fetchSelectedAgent();
        } else {
            throw new Error('Failed to select agent');
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error selecting agent');
    });
}

function fetchSelectedAgent() {
    fetch('/api/selected_agent')
    .then(response => response.json())
    .then(data => {
        const selectedAgentName = document.getElementById('selected-agent-name');
        if (data.selected_agent) {
            selectedAgentName.textContent = data.selected_agent.name;
        } else {
            selectedAgentName.textContent = 'None';
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        selectedAgentName.textContent = 'Error fetching selected agent';
    });
}