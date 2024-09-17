document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const processesTable = document.getElementById('processes-table');
    const processesTableBody = processesTable.getElementsByTagName('tbody')[0];
    const selectAgentBtn = document.getElementById('select-agent-btn');
    const refreshDataBtn = document.getElementById('refresh-data-btn');
    const refreshInterval = 5000; // Refresh every 5 seconds
    let selectedAgentId = null;
    let isLoading = false;

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
            .catch(error => {
                console.error('Error fetching agents:', error);
                showAlert('Error fetching agents. Please try again.');
            });
    }

    function selectAgent(agentId) {
        fetch(`/select_agent/${agentId}`, { method: 'POST' })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to select agent');
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
                resetAgentSelection();
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
                    throw new Error('Failed to fetch processes');
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
                showAlert(`Error fetching processes: ${error.message}. Please select an agent again.`);
                resetAgentSelection();
            });
    }

    function updateProcessesTable(processes) {
        clearProcessesTable();
        if (!Array.isArray(processes) || processes.length === 0) {
            showAlert('No processes found for this agent.');
            return;
        }

        const fragment = document.createDocumentFragment();
        processes.forEach((process) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(process.pid)}</td>
                <td>${escapeHtml(process.name)}</td>
                <td>${escapeHtml(process.username)}</td>
                <td>${process.cpu_percent ? process.cpu_percent.toFixed(2) : 'N/A'}</td>
                <td>${process.memory_percent ? process.memory_percent.toFixed(2) : 'N/A'}</td>
            `;
            fragment.appendChild(row);
        });
        processesTableBody.appendChild(fragment);
    }

    function clearProcessesTable() {
        processesTableBody.innerHTML = '';
    }

    function showAlert(message) {
        clearProcessesTable();
        const alertRow = processesTableBody.insertRow();
        alertRow.innerHTML = `<td colspan="5" class="alert-message">${escapeHtml(message)}</td>`;
    }

    function resetAgentSelection() {
        selectedAgentId = null;
        agentSelect.value = '';
        clearProcessesTable();
    }

    function escapeHtml(unsafe) {
        if (unsafe == null) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    selectAgentBtn.addEventListener('click', function() {
        const agentId = agentSelect.value;
        if (agentId) {
            selectAgent(agentId);
        } else {
            showAlert('Please select an agent');
        }
    });

    refreshDataBtn.addEventListener('click', function() {
        if (selectedAgentId) {
            fetchProcesses();
        } else {
            showAlert('Please select an agent first');
        }
    });

    // Initial fetch of agents
    fetchAgents();

    // We'll remove the automatic refresh to avoid unwanted requests
    // If you still want periodic updates, you can uncomment the following:
    /*
    setInterval(() => {
        if (selectedAgentId) {
            fetchProcesses();
        }
    }, refreshInterval);
    */
});