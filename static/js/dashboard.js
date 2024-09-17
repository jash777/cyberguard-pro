document.addEventListener('DOMContentLoaded', function() {
    updateDashboardCounts();
    createSystemLoadChart();
});

function updateDashboardCounts() {
    const countElements = {
        'agent-count': '/api/agents',
        'process-count': '/api/processes',
        'user-count': '/api/users',
        'app-count': '/api/applications'
    };

    Object.entries(countElements).forEach(([elementId, endpoint]) => {
        const element = document.getElementById(elementId);
        if (element) {
            fetch(endpoint)
                .then(handleResponse)
                .then(data => {
                    element.querySelector('.large-number').textContent = data.length;
                })
                .catch(error => showError(`Error updating ${elementId}:`, error));
        }
    });
}

function createSystemLoadChart() {
    const ctx = document.getElementById('system-load-chart')?.getContext('2d');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['1m', '5m', '15m', '30m', '1h', '2h'],
            datasets: [{
                label: 'CPU Load',
                data: [65, 59, 80, 81, 56, 55],
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
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
    showAlert(`${message} ${error.message || 'Unknown error'}`);
}