document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const processesTable = document.getElementById('processes-table')?.getElementsByTagName('tbody')[0];
    const refreshInterval = 5000; // Refresh every 5 seconds
    let selectedAgentId = null;

    // Initialize components based on the current page
    updateClock();
    setInterval(updateClock, 1000);

    if (document.getElementById('dashboard-counts')) {
        updateDashboardCounts();
        setInterval(updateDashboardCounts, refreshInterval);
    }

    if (document.getElementById('system-load-chart')) {
        createSystemLoadChart();
    }

    if (agentSelect) {
        fetchAgents();
        agentSelect.addEventListener('change', handleAgentSelection);
    }

    if (processesTable) {
        setInterval(() => {
            if (selectedAgentId) {
                fetchProcesses();
            }
        }, refreshInterval);
    }

    function updateClock() {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        const dateString = now.toLocaleDateString();
        document.getElementById('current-time').textContent = `${dateString} ${timeString}`;
    }