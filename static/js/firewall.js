document.addEventListener('DOMContentLoaded', function() {
    loadFirewallRules();
    
    const addRuleBtn = document.getElementById('add-rule-btn');
    const addRuleModal = document.getElementById('add-rule-modal');
    const addRuleForm = document.getElementById('add-rule-form');

    addRuleBtn.addEventListener('click', () => {
        addRuleModal.style.display = 'block';
    });

    addRuleForm.addEventListener('submit', (e) => {
        e.preventDefault();
        addFirewallRule();
    });

    window.onclick = (event) => {
        if (event.target == addRuleModal) {
            addRuleModal.style.display = 'none';
        }
    };
});
function fetchAgents() {
    fetch('/api/agents')
        .then(response => response.json())
        .then(agents => {
            agentSelect.innerHTML = '<option value="">Select an agent</option>';
            agents.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.textContent = `${agent.name} (${agent.ip_address})`;
                agentSelect.appendChild(option);
            });
        })
        .catch(error => console.error('Error fetching agents:', error));
}

function loadFirewallRules() {
    fetch('/api/firewall_rules')
        .then(response => response.json())
        .then(rules => {
            const tableBody = document.querySelector('#firewall-table tbody');
            tableBody.innerHTML = '';
            rules.forEach(rule => {
                const row = createRuleRow(rule);
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading firewall rules:', error));
}

function createRuleRow(rule) {
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${rule.protocol}</td>
        <td>${rule.port}</td>
        <td>${rule.action}</td>
        <td>${rule.source || 'Any'}</td>
        <td>${rule.destination || 'Any'}</td>
        <td>
            <button class="btn btn-small btn-danger" onclick="removeFirewallRule(${rule.id})">Remove</button>
        </td>
    `;
    return row;
}

function addFirewallRule() {
    const protocol = document.getElementById('rule-protocol').value;
    const port = document.getElementById('rule-port').value;
    const action = document.getElementById('rule-action').value;
    const source = document.getElementById('rule-source').value;
    const destination = document.getElementById('rule-destination').value;

    const rule = {
        protocol: protocol,
        destination_port: port,
        action: action,
        source: source || null,
        destination: destination || null
    };

    fetch('/api/firewall_rules', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(rule),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'completed' && data.results[0].success) {
            alert('Firewall rule added successfully');
            loadFirewallRules();
            document.getElementById('add-rule-modal').style.display = 'none';
            document.getElementById('add-rule-form').reset();
        } else {
            alert('Failed to add firewall rule');
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error adding firewall rule');
    });
}

function removeFirewallRule(ruleId) {
    if (confirm('Are you sure you want to remove this firewall rule?')) {
        fetch(`/api/firewall_rules?id=${ruleId}`, {
            method: 'DELETE',
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            loadFirewallRules();
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('Error removing firewall rule');
        });
    }
}

function blockPort() {
    const port = document.getElementById('block-port-input').value;
    
    fetch('/api/block_port', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ port: port }),
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        loadFirewallRules();
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error blocking port');
    });
}

document.addEventListener('DOMContentLoaded', function() {
    loadFirewallRules();
    
    const addRuleBtn = document.getElementById('add-rule-btn');
    const addRuleModal = document.getElementById('add-rule-modal');
    const addRuleForm = document.getElementById('add-rule-form');

    addRuleBtn.addEventListener('click', () => {
        addRuleModal.style.display = 'block';
    });

    addRuleForm.addEventListener('submit', (e) => {
        e.preventDefault();
        addFirewallRule();
    });

    window.onclick = (event) => {
        if (event.target == addRuleModal) {
            addRuleModal.style.display = 'none';
        }
    };
});

function loadFirewallRules() {
    fetch('/api/firewall_rules')
        .then(response => response.json())
        .then(rules => {
            const tableBody = document.querySelector('#firewall-table tbody');
            tableBody.innerHTML = '';
            rules.forEach(rule => {
                const row = createRuleRow(rule);
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading firewall rules:', error));
}

function createRuleRow(rule) {
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${rule.protocol}</td>
        <td>${rule.destination_port}</td>
        <td>${rule.action}</td>
        <td>${rule.source || 'Any'}</td>
        <td>${rule.destination || 'Any'}</td>
        <td>
            <button class="btn btn-small btn-danger" onclick="removeRule(${rule.id})">Remove</button>
        </td>
    `;
    return row;
}

function addFirewallRule() {
    const rule = {
        protocol: document.getElementById('rule-protocol').value,
        destination_port: document.getElementById('rule-destination-port').value,
        action: document.getElementById('rule-action').value,
        source: document.getElementById('rule-source').value || null,
        destination: document.getElementById('rule-destination').value || null
    };

    fetch('/api/firewall_rules', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rules: [rule] }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'completed' && data.results[0].success) {
            alert('Firewall rule added successfully');
            loadFirewallRules();
            document.getElementById('add-rule-modal').style.display = 'none';
            document.getElementById('add-rule-form').reset();
        } else {
            alert('Failed to add firewall rule');
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error adding firewall rule');
    });
}

function removeRule(ruleId) {
    if (confirm('Are you sure you want to remove this firewall rule?')) {
        fetch(`/api/firewall_rules?id=${ruleId}`, {
            method: 'DELETE',
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            loadFirewallRules();
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('Error removing firewall rule');
        });
    }
}