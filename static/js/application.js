document.addEventListener('DOMContentLoaded', function() {
    loadSelectedAgent();
    loadApplications();

    document.getElementById('app-search').addEventListener('input', function() {
        filterApplications(this.value);
    });

    document.getElementById('close-update-modal').addEventListener('click', closeUpdateModal);
});

function loadSelectedAgent() {
    fetch('/get_selected_agent')
        .then(response => response.json())
        .then(data => {
            const agentName = document.getElementById('selected-agent-name');
            if (data.selected_agent) {
                agentName.textContent = `${data.selected_agent.name} (${data.selected_agent.ip_address})`;
            } else {
                agentName.textContent = 'None';
            }
        })
        .catch(error => console.error('Error loading selected agent:', error));
}

function loadApplications() {
    fetch('/get_applications')
        .then(response => response.json())
        .then(data => {
            console.log('Received data:', data); // Add this line for debugging
            if (data.applications && Array.isArray(data.applications)) {
                populateApplicationsTable(data.applications);
            } else {
                console.error('No applications data received or data is not an array:', data);
                document.getElementById('applications-body').innerHTML = '<tr><td colspan="3">No applications data available</td></tr>';
            }
        })
        .catch(error => {
            console.error('Error loading applications:', error);
            document.getElementById('applications-body').innerHTML = '<tr><td colspan="3">Error loading applications</td></tr>';
        });
}

function populateApplicationsTable(applications) {
    const tableBody = document.getElementById('applications-body');
    tableBody.innerHTML = '';

    if (applications.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="3">No applications found</td></tr>';
        return;
    }

    applications.forEach(app => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${app.name || 'Unknown'}</td>
            <td>${app.version || 'Unknown'}</td>
            <td>
                <button class="btn btn-small" onclick="checkForUpdates('${app.name}')">Check for Updates</button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

function filterApplications(searchTerm) {
    const rows = document.querySelectorAll('#applications-body tr');
    rows.forEach(row => {
        const name = row.cells[0].textContent.toLowerCase();
        if (name.includes(searchTerm.toLowerCase())) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

function checkForUpdates(appName) {
    // This is a placeholder function. In a real-world scenario, you would make an API call to check for updates.
    const updateModal = document.getElementById('update-modal');
    const updateMessage = document.getElementById('update-message');
    updateMessage.textContent = `Checking for updates for ${appName}...`;
    updateModal.style.display = 'block';

    // Simulate an API call
    setTimeout(() => {
        updateMessage.textContent = `No updates available for ${appName}.`;
    }, 2000);
}

function closeUpdateModal() {
    document.getElementById('update-modal').style.display = 'none';
}