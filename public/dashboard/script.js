/**
 * AWS Security Group Risk Dashboard
 * Main JavaScript Application
 * 
 * Features:
 * - Fetches and parses security_analysis.json
 * - Displays summary metrics
 * - Renders sortable, searchable, paginated data table
 * - Draws risk distribution chart (pure Canvas)
 * - Handles navigation and responsive sidebar
 */

// ============================================
// Application State
// ============================================
const state = {
    data: [],
    filteredData: [],
    currentPage: 1,
    itemsPerPage: 10,
    sortColumn: 'Risk',
    sortDirection: 'desc',
    searchQuery: '',
    metrics: {
        totalGroups: 0,
        totalPublic: 0,
        allowedRules: 0,
        highRiskRules: 0
    }
};

// ============================================
// DOM Elements
// ============================================
const elements = {
    // Loading
    loadingOverlay: document.getElementById('loadingOverlay'),
    
    // Metrics
    totalGroups: document.getElementById('totalGroups'),
    totalPublic: document.getElementById('totalPublic'),
    allowedRules: document.getElementById('allowedRules'),
    highRiskRules: document.getElementById('highRiskRules'),
    
    // Table
    dataTable: document.getElementById('dataTable'),
    tableBody: document.getElementById('tableBody'),
    emptyState: document.getElementById('emptyState'),
    searchInput: document.getElementById('searchInput'),
    paginationInfo: document.getElementById('paginationInfo'),
    pagination: document.getElementById('pagination'),
    
    // Chart
    riskChart: document.getElementById('riskChart'),
    chartLegend: document.getElementById('chartLegend'),
    
    // Navigation
    sidebar: document.getElementById('sidebar'),
    menuToggle: document.getElementById('menuToggle'),
    navItems: document.querySelectorAll('.nav-item'),
    dashboardPage: document.getElementById('dashboardPage'),
    reportsPage: document.getElementById('reportsPage'),
    
    // Other
    refreshBtn: document.getElementById('refreshBtn'),
    lastScanTime: document.getElementById('lastScanTime'),
    tooltip: document.getElementById('tooltip')
};

// ============================================
// Utility Functions
// ============================================

/**
 * Determines if a port is considered "allowed" for public access
 * Only ports 80 (HTTP) and 443 (HTTPS) are allowed
 */
function isAllowedPort(portRange) {
    const port = String(portRange).trim();
    return port === '80' || port === '443';
}

/**
 * Calculates risk level based on port
 */
function calculateRiskLevel(portRange) {
    return isAllowedPort(portRange) ? 'ALLOWED' : 'HIGH RISK';
}

/**
 * Gets tooltip text explaining why a rule has its risk level
 */
function getRiskTooltip(risk, portRange) {
    if (risk === 'ALLOWED' || risk === 'Allowed') {
        return `Port ${portRange} is a standard web port (HTTP/HTTPS) and is considered safe for public access.`;
    }
    return `Port ${portRange} is exposed to the entire internet (0.0.0.0/0). This is a security risk as it allows unrestricted access to potentially sensitive services.`;
}

/**
 * Formats date for display
 */
function formatDate(date) {
    return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

/**
 * Debounce function for search input
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================
// Data Loading
// ============================================

/**
 * Fetches security analysis data from JSON file
 */
async function loadData() {
    showLoading(true);
    
    try {
        const response = await fetch('security_analysis.json');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Process and normalize data
        state.data = data.map(item => ({
            ...item,
            // Recalculate risk based on our logic to ensure consistency
            Risk: calculateRiskLevel(item.PortRange)
        }));
        
        state.filteredData = [...state.data];
        
        // Update UI
        calculateMetrics();
        updateMetricsDisplay();
        applySort();
        renderTable();
        drawChart();
        updateLastScanTime();
        
    } catch (error) {
        console.error('Error loading data:', error);
        showEmptyState(true);
        updateMetricsDisplay({ totalGroups: 0, totalPublic: 0, allowedRules: 0, highRiskRules: 0 });
    } finally {
        showLoading(false);
    }
}

/**
 * Shows or hides loading overlay
 */
function showLoading(show) {
    if (show) {
        elements.loadingOverlay.classList.remove('hidden');
    } else {
        elements.loadingOverlay.classList.add('hidden');
    }
}

/**
 * Shows or hides empty state
 */
function showEmptyState(show) {
    elements.emptyState.style.display = show ? 'flex' : 'none';
    elements.dataTable.style.display = show ? 'none' : 'table';
}

// ============================================
// Metrics Calculation
// ============================================

/**
 * Calculates summary metrics from data
 */
function calculateMetrics() {
    // Get unique security groups
    const uniqueGroups = new Set(state.data.map(item => item.SecurityGroupId));
    
    state.metrics = {
        totalGroups: uniqueGroups.size,
        totalPublic: state.data.length,
        allowedRules: state.data.filter(item => 
            item.Risk === 'ALLOWED' || item.Risk === 'Allowed'
        ).length,
        highRiskRules: state.data.filter(item => 
            item.Risk === 'HIGH RISK' || item.Risk === 'High Risk'
        ).length
    };
}

/**
 * Updates metrics display in UI
 */
function updateMetricsDisplay() {
    // Animate counter
    animateCounter(elements.totalGroups, state.metrics.totalGroups);
    animateCounter(elements.totalPublic, state.metrics.totalPublic);
    animateCounter(elements.allowedRules, state.metrics.allowedRules);
    animateCounter(elements.highRiskRules, state.metrics.highRiskRules);
}

/**
 * Animates a counter from 0 to target value
 */
function animateCounter(element, target) {
    const duration = 500;
    const start = 0;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Ease out cubic
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (target - start) * easeOut);
        
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

/**
 * Updates last scan time display
 */
function updateLastScanTime() {
    elements.lastScanTime.textContent = formatDate(new Date());
}

// ============================================
// Table Rendering
// ============================================

/**
 * Renders the data table with current filtered/sorted data
 */
function renderTable() {
    const { filteredData, currentPage, itemsPerPage } = state;
    
    // Check for empty data
    if (filteredData.length === 0) {
        showEmptyState(true);
        updatePaginationInfo(0, 0, 0);
        renderPagination(0);
        return;
    }
    
    showEmptyState(false);
    
    // Calculate pagination
    const totalItems = filteredData.length;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, totalItems);
    const pageData = filteredData.slice(startIndex, endIndex);
    
    // Build table HTML
    let html = '';
    
    pageData.forEach(item => {
        const isRisk = item.Risk === 'HIGH RISK' || item.Risk === 'High Risk';
        const badgeClass = isRisk ? 'badge-risk' : 'badge-allowed';
        const badgeText = isRisk ? 'High Risk' : 'Allowed';
        const tooltipText = getRiskTooltip(item.Risk, item.PortRange);
        
        html += `
            <tr>
                <td class="sg-name">${escapeHtml(item.SecurityGroupName)}</td>
                <td class="sg-id">${escapeHtml(item.SecurityGroupId)}</td>
                <td class="protocol">${escapeHtml(item.Protocol)}</td>
                <td>${escapeHtml(item.PortRange)}</td>
                <td class="cidr">${escapeHtml(item.OpenTo)}</td>
                <td>
                    <span class="badge ${badgeClass}" 
                          data-tooltip="${escapeHtml(tooltipText)}">
                        ${isRisk ? 
                            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' : 
                            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
                        }
                        ${badgeText}
                    </span>
                </td>
            </tr>
        `;
    });
    
    elements.tableBody.innerHTML = html;
    
    // Update pagination
    updatePaginationInfo(startIndex + 1, endIndex, totalItems);
    renderPagination(totalPages);
    
    // Add tooltip listeners
    addTooltipListeners();
}

/**
 * Escapes HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Updates pagination info text
 */
function updatePaginationInfo(start, end, total) {
    elements.paginationInfo.textContent = `Showing ${start}-${end} of ${total} rules`;
}

/**
 * Renders pagination buttons
 */
function renderPagination(totalPages) {
    if (totalPages <= 1) {
        elements.pagination.innerHTML = '';
        return;
    }
    
    const { currentPage } = state;
    let html = '';
    
    // Previous button
    html += `<button ${currentPage === 1 ? 'disabled' : ''} data-page="prev">←</button>`;
    
    // Page buttons
    const maxVisible = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
    let endPage = Math.min(totalPages, startPage + maxVisible - 1);
    
    if (endPage - startPage < maxVisible - 1) {
        startPage = Math.max(1, endPage - maxVisible + 1);
    }
    
    if (startPage > 1) {
        html += `<button data-page="1">1</button>`;
        if (startPage > 2) {
            html += `<button disabled>...</button>`;
        }
    }
    
    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
    }
    
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += `<button disabled>...</button>`;
        }
        html += `<button data-page="${totalPages}">${totalPages}</button>`;
    }
    
    // Next button
    html += `<button ${currentPage === totalPages ? 'disabled' : ''} data-page="next">→</button>`;
    
    elements.pagination.innerHTML = html;
}

// ============================================
// Table Sorting
// ============================================

/**
 * Applies current sort to data
 */
function applySort() {
    const { sortColumn, sortDirection, filteredData } = state;
    
    filteredData.sort((a, b) => {
        let valueA = a[sortColumn];
        let valueB = b[sortColumn];
        
        // Handle string comparison
        if (typeof valueA === 'string') {
            valueA = valueA.toLowerCase();
            valueB = valueB.toLowerCase();
        }
        
        // Handle numeric port ranges
        if (sortColumn === 'PortRange') {
            valueA = parseInt(valueA) || 0;
            valueB = parseInt(valueB) || 0;
        }
        
        if (valueA < valueB) return sortDirection === 'asc' ? -1 : 1;
        if (valueA > valueB) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });
}

/**
 * Handles sort column click
 */
function handleSort(column) {
    // Toggle direction if same column, otherwise default to asc
    if (state.sortColumn === column) {
        state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        state.sortColumn = column;
        state.sortDirection = 'asc';
    }
    
    // Update sort indicators
    updateSortIndicators();
    
    // Re-sort and render
    applySort();
    state.currentPage = 1;
    renderTable();
}

/**
 * Updates sort indicator classes on table headers
 */
function updateSortIndicators() {
    const headers = elements.dataTable.querySelectorAll('th.sortable');
    
    headers.forEach(header => {
        header.classList.remove('sort-asc', 'sort-desc');
        
        if (header.dataset.sort === state.sortColumn) {
            header.classList.add(state.sortDirection === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    });
}

// ============================================
// Table Search
// ============================================

/**
 * Filters data based on search query
 */
function handleSearch(query) {
    state.searchQuery = query.toLowerCase().trim();
    
    if (!state.searchQuery) {
        state.filteredData = [...state.data];
    } else {
        state.filteredData = state.data.filter(item => {
            return (
                item.SecurityGroupName.toLowerCase().includes(state.searchQuery) ||
                item.SecurityGroupId.toLowerCase().includes(state.searchQuery) ||
                item.Protocol.toLowerCase().includes(state.searchQuery) ||
                String(item.PortRange).includes(state.searchQuery) ||
                item.OpenTo.includes(state.searchQuery) ||
                item.Risk.toLowerCase().includes(state.searchQuery)
            );
        });
    }
    
    state.currentPage = 1;
    applySort();
    renderTable();
}

// ============================================
// Chart Drawing
// ============================================

/**
 * Draws pie chart showing risk distribution
 */
function drawChart() {
    const canvas = elements.riskChart;
    const ctx = canvas.getContext('2d');
    
    // Get device pixel ratio for crisp rendering
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const radius = Math.min(centerX, centerY) - 20;
    
    const { allowedRules, highRiskRules } = state.metrics;
    const total = allowedRules + highRiskRules;
    
    // Clear canvas
    ctx.clearRect(0, 0, rect.width, rect.height);
    
    if (total === 0) {
        // Draw empty state
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
        ctx.fillStyle = '#e2e8f0';
        ctx.fill();
        
        ctx.fillStyle = '#94a3b8';
        ctx.font = '14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No data', centerX, centerY);
        
        updateChartLegend(0, 0);
        return;
    }
    
    // Draw pie slices
    const slices = [
        { value: allowedRules, color: '#10b981', label: 'Allowed' },
        { value: highRiskRules, color: '#ef4444', label: 'High Risk' }
    ];
    
    let startAngle = -Math.PI / 2; // Start from top
    
    slices.forEach(slice => {
        if (slice.value === 0) return;
        
        const sliceAngle = (slice.value / total) * Math.PI * 2;
        
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = slice.color;
        ctx.fill();
        
        // Add subtle shadow effect
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        startAngle += sliceAngle;
    });
    
    // Draw center circle (donut effect)
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * 0.6, 0, Math.PI * 2);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
    
    // Draw center text
    ctx.fillStyle = '#0f172a';
    ctx.font = 'bold 28px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, centerX, centerY - 8);
    
    ctx.fillStyle = '#64748b';
    ctx.font = '12px Inter, sans-serif';
    ctx.fillText('Total Rules', centerX, centerY + 16);
    
    // Update legend
    updateChartLegend(allowedRules, highRiskRules);
}

/**
 * Updates chart legend
 */
function updateChartLegend(allowed, risk) {
    elements.chartLegend.innerHTML = `
        <div class="legend-item">
            <span class="legend-color allowed"></span>
            <span>Allowed (${allowed})</span>
        </div>
        <div class="legend-item">
            <span class="legend-color risk"></span>
            <span>High Risk (${risk})</span>
        </div>
    `;
}

// ============================================
// Tooltip Handling
// ============================================

/**
 * Adds tooltip event listeners to badges
 */
function addTooltipListeners() {
    const badges = elements.tableBody.querySelectorAll('.badge[data-tooltip]');
    
    badges.forEach(badge => {
        badge.addEventListener('mouseenter', showTooltip);
        badge.addEventListener('mouseleave', hideTooltip);
        badge.addEventListener('mousemove', moveTooltip);
    });
}

/**
 * Shows tooltip
 */
function showTooltip(e) {
    const tooltipText = e.target.closest('.badge').dataset.tooltip;
    elements.tooltip.textContent = tooltipText;
    elements.tooltip.classList.add('visible');
    moveTooltip(e);
}

/**
 * Hides tooltip
 */
function hideTooltip() {
    elements.tooltip.classList.remove('visible');
}

/**
 * Moves tooltip to follow cursor
 */
function moveTooltip(e) {
    const x = e.clientX + 10;
    const y = e.clientY + 10;
    
    // Keep tooltip on screen
    const tooltipRect = elements.tooltip.getBoundingClientRect();
    const maxX = window.innerWidth - tooltipRect.width - 20;
    const maxY = window.innerHeight - tooltipRect.height - 20;
    
    elements.tooltip.style.left = `${Math.min(x, maxX)}px`;
    elements.tooltip.style.top = `${Math.min(y, maxY)}px`;
}

// ============================================
// Navigation
// ============================================

/**
 * Handles page navigation
 */
function navigateTo(page) {
    // Update nav items
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // Show/hide pages
    elements.dashboardPage.classList.toggle('hidden', page !== 'dashboard');
    elements.reportsPage.classList.toggle('hidden', page !== 'reports');
    
    // Close mobile sidebar
    elements.sidebar.classList.remove('open');
}

/**
 * Toggles mobile sidebar
 */
function toggleSidebar() {
    elements.sidebar.classList.toggle('open');
}

// ============================================
// Event Listeners
// ============================================

/**
 * Initializes all event listeners
 */
function initEventListeners() {
    // Search input
    elements.searchInput.addEventListener('input', debounce((e) => {
        handleSearch(e.target.value);
    }, 300));
    
    // Sort headers
    elements.dataTable.querySelectorAll('th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            handleSort(th.dataset.sort);
        });
    });
    
    // Pagination
    elements.pagination.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn || btn.disabled) return;
        
        const page = btn.dataset.page;
        const totalPages = Math.ceil(state.filteredData.length / state.itemsPerPage);
        
        if (page === 'prev') {
            state.currentPage = Math.max(1, state.currentPage - 1);
        } else if (page === 'next') {
            state.currentPage = Math.min(totalPages, state.currentPage + 1);
        } else {
            state.currentPage = parseInt(page);
        }
        
        renderTable();
    });
    
    // Navigation
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(item.dataset.page);
        });
    });
    
    // Mobile menu toggle
    elements.menuToggle.addEventListener('click', toggleSidebar);
    
    // Refresh button
    elements.refreshBtn.addEventListener('click', loadData);
    
    // Window resize for chart
    window.addEventListener('resize', debounce(() => {
        drawChart();
    }, 250));
    
    // Close sidebar on outside click (mobile)
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 768) {
            if (!elements.sidebar.contains(e.target) && 
                !elements.menuToggle.contains(e.target) &&
                elements.sidebar.classList.contains('open')) {
                elements.sidebar.classList.remove('open');
            }
        }
    });
}

// ============================================
// Initialization
// ============================================

/**
 * Initialize application
 */
function init() {
    initEventListeners();
    updateSortIndicators();
    loadData();
}

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', init);
