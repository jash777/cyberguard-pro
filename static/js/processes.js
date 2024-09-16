document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const processesTable = document.getElementById('processes-table').getElementsByTagName('tbody')[0];
    const refreshInterval = 5000; // Refresh every 5 seconds
    let selectedAgentId = null;

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

    function selectAgent(agentId) {
        fetch(`/select_agent/${agentId}`, { method: 'POST' })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw err; });
                }
                return response.json();
            })
            .then(data => {
                console.log('Agent selected successfully:', data);
                selectedAgentId = agentId;
                fetchProcesses();
            })
            .catch(error => {
                console.error('Error selecting agent:', error);
                showAlert(`Error selecting agent: ${error.message || 'Unknown error'}`);
            });
    }
    function fetchProcesses() {
        if (!selectedAgentId) {
            showAlert('Please select an agent first.');
            return;
        }
    
        fetch('/api/processes')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw err; });
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }
                updateProcessesTable(data);
            })
            .catch(error => {
                console.error('Error fetching processes:', error);
                if (error.message.includes('No agent selected')) {
                    showAlert('Please select an agent first.');
                } else if (error.message.includes('Processes not enabled')) {
                    showAlert('Processes are not enabled for this agent.');
                } else {
                    showAlert(`Error fetching processes: ${error.message}`);
                }
                clearProcessesTable();
            });
    }

    function updateProcessesTable(processes) {
        clearProcessesTable();

        if (processes.length === 0) {
            showAlert('No processes found for this agent.');
            return;
        }

        processes.forEach(process => {
            const row = processesTable.insertRow();
            row.innerHTML = `
                <td>${process.pid}</td>
                <td>${process.name}</td>
                <td>${process.username}</td>
                <td>${process.cpu_percent ? process.cpu_percent.toFixed(2) : 'N/A'}</td>
                <td>${process.memory_percent ? process.memory_percent.toFixed(2) : 'N/A'}</td>
            `;
        });
    }

    function clearProcessesTable() {
        processesTable.innerHTML = '';
    }

    function showAlert(message) {
        clearProcessesTable();
        const alertRow = processesTable.insertRow();
        alertRow.innerHTML = `<td colspan="5" class="alert-message">${message}</td>`;
    }

    agentSelect.addEventListener('change', function() {
        const selectedAgentId = this.value;
        if (selectedAgentId) {
            selectAgent(selectedAgentId);
        } else {
            clearProcessesTable();
            showAlert('Please select an agent');
        }
    });

    // Initial fetch of agents
    fetchAgents();

    // Set up periodic refresh of processes only if an agent is selected
    setInterval(() => {
        if (selectedAgentId) {
            fetchProcesses();
        }
    }, refreshInterval);
});