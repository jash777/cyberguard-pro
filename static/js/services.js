document.addEventListener('DOMContentLoaded', function() {
    const agentSelect = document.getElementById('agent-select');
    const servicesTable = document.getElementById('services-table');
    const servicesTableBody = servicesTable.querySelector('tbody');
    const selectAgentBtn = document.getElementById('select-agent-btn');
    const refreshDataBtn = document.getElementById('refresh-data-btn');
    const searchInput = document.getElementById('service-search');
    const categoryFilter = document.getElementById('category-filter');
    const selectedAgentNameSpan = document.getElementById('selected-agent-name');
    const serviceModal = document.getElementById('service-modal');
    const serviceMessage = document.getElementById('service-message');
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    const currentPageSpan = document.getElementById('current-page');
    const totalPagesSpan = document.getElementById('total-pages');

    let selectedAgentId = null;
    let services = [];
    let currentPage = 1;
    const itemsPerPage = 20;

    function fetchAgents() {
        fetch('/api/agents')
            .then(response => response.json())
            .then(agents => {
                const fragment = document.createDocumentFragment();
                fragment.appendChild(new Option('Select an agent', ''));
                agents.forEach(agent => {
                    fragment.appendChild(new Option(`${agent.name} (${agent.ip_address})`, agent.id));
                });
                agentSelect.innerHTML = '';
                agentSelect.appendChild(fragment);
            })
            .catch(error => {
                console.error('Error fetching agents:', error);
                showAlert('Error fetching agents. Please try again.');
            });
    }

    function selectAgent(agentId) {
        fetch(`/select_agent/${agentId}`, { method: 'POST' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to select agent');
                return response.json();
            })
            .then(data => {
                console.log('Agent selected successfully:', data);
                selectedAgentId = agentId;
                selectedAgentNameSpan.textContent = data.agent;
                loadServices();
            })
            .catch(error => {
                console.error('Error selecting agent:', error);
                showAlert(`Error selecting agent: ${error.message || 'Unknown error'}`);
                resetAgentSelection();
            });
    }

    function loadServices() {
        if (!selectedAgentId) {
            showAlert('Please select an agent first.');
            return;
        }

        fetch('/api/services')
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch services');
                return response.json();
            })
            .then(data => {
                if (data.error) throw new Error(data.error);
                services = data.services;
                currentPage = 1;
                updateServicesTable();
                populateCategoryFilter(services);
            })
            .catch(error => {
                console.error('Error fetching services:', error);
                showAlert(`Error fetching services: ${error.message}. Please select an agent again.`);
                resetAgentSelection();
            });
    }

    function updateServicesTable() {
        clearServicesTable();
        const filteredServices = filterServices();
        const totalPages = Math.ceil(filteredServices.length / itemsPerPage);
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const servicesToShow = filteredServices.slice(startIndex, endIndex);

        if (servicesToShow.length === 0) {
            showAlert('No services found for this agent.');
            return;
        }

        const fragment = document.createDocumentFragment();
        servicesToShow.forEach((service) => {
            const row = fragment.appendChild(document.createElement('tr'));
            row.innerHTML = `
                <td>${escapeHtml(service.name)}</td>
                <td>${escapeHtml(service.category)}</td>
            `;
            row.addEventListener('click', () => showServiceDetails(service));
        });
        servicesTableBody.appendChild(fragment);

        updatePagination(totalPages);
    }

    function updatePagination(totalPages) {
        currentPageSpan.textContent = currentPage;
        totalPagesSpan.textContent = totalPages;
        prevPageBtn.disabled = currentPage === 1;
        nextPageBtn.disabled = currentPage === totalPages;
    }

    function populateCategoryFilter(services) {
        const categories = [...new Set(services.map(service => service.category))];
        const fragment = document.createDocumentFragment();
        fragment.appendChild(new Option('All Categories', ''));
        categories.forEach(category => {
            fragment.appendChild(new Option(category, category));
        });
        categoryFilter.innerHTML = '';
        categoryFilter.appendChild(fragment);
    }

    function clearServicesTable() {
        servicesTableBody.innerHTML = '';
    }

    function showAlert(message) {
        clearServicesTable();
        const alertRow = servicesTableBody.insertRow();
        alertRow.innerHTML = `<td colspan="2" class="alert-message">${escapeHtml(message)}</td>`;
    }

    function resetAgentSelection() {
        selectedAgentId = null;
        agentSelect.value = '';
        selectedAgentNameSpan.textContent = 'None';
        clearServicesTable();
        categoryFilter.innerHTML = '<option value="">All Categories</option>';
        currentPage = 1;
        updatePagination(1);
    }

    const escapeHtml = (function() {
        const entityMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        };
        return function(string) {
            return String(string).replace(/[&<>"'`=\/]/g, function(s) {
                return entityMap[s];
            });
        };
    })();

    function showServiceDetails(service) {
        serviceMessage.innerHTML = `
            <strong>Name:</strong> ${escapeHtml(service.name)}<br>
            <strong>Category:</strong> ${escapeHtml(service.category)}
        `;
        serviceModal.style.display = 'block';
    }

    function closeServiceModal() {
        serviceModal.style.display = 'none';
    }

    function filterServices() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedCategory = categoryFilter.value;
        return services.filter(service => {
            const nameMatch = service.name.toLowerCase().includes(searchTerm);
            const categoryMatch = !selectedCategory || service.category === selectedCategory;
            return nameMatch && categoryMatch;
        });
    }

    selectAgentBtn.addEventListener('click', () => {
        const agentId = agentSelect.value;
        agentId ? selectAgent(agentId) : showAlert('Please select an agent');
    });

    refreshDataBtn.addEventListener('click', () => {
        selectedAgentId ? loadServices() : showAlert('Please select an agent first');
    });

    searchInput.addEventListener('input', () => {
        currentPage = 1;
        updateServicesTable();
    });

    categoryFilter.addEventListener('change', () => {
        currentPage = 1;
        updateServicesTable();
    });

    prevPageBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            updateServicesTable();
        }
    });

    nextPageBtn.addEventListener('click', () => {
        const filteredServices = filterServices();
        const totalPages = Math.ceil(filteredServices.length / itemsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            updateServicesTable();
        }
    });

    document.getElementById('close-service-modal').addEventListener('click', closeServiceModal);

    // Initial fetch of agents
    fetchAgents();
});