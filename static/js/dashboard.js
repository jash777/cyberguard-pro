document.addEventListener('DOMContentLoaded', function() {
    updateDashboardCounts();
    createSystemLoadChart();
});

function updateDashboardCounts() {
    fetch('/api/agents')
        .then(response => response.json())
        .then(data => {
            document.getElementById('agent-count').querySelector('.large-number').textContent = data.length;
        });

    fetch('/api/processes')
        .then(response => response.json())
        .then(data => {
            document.getElementById('process-count').querySelector('.large-number').textContent = data.length;
        });

    fetch('/api/users')
        .then(response => response.json())
        .then(data => {
            document.getElementById('user-count').querySelector('.large-number').textContent = data.length;
        });

    fetch('/api/applications')
        .then(response => response.json())
        .then(data => {
            document.getElementById('app-count').querySelector('.large-number').textContent = data.length;
        });
}

function createSystemLoadChart() {
    const ctx = document.getElementById('system-load-chart').getContext('2d');
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