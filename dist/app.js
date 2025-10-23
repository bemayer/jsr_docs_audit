import init, { audit_package } from './pkg/audit_script.js';

// State management
const state = {
    wasmReady: false,
    currentSearch: null,
    autocompleteTimeout: null,
    selectedIndex: -1,
    autocompleteResults: []
};

// DOM elements
const elements = {
    packageInput: document.getElementById('package-input'),
    auditButton: document.getElementById('audit-button'),
    autocompleteDropdown: document.getElementById('autocomplete-dropdown'),
    loading: document.getElementById('loading'),
    error: document.getElementById('error'),
    resultsSection: document.getElementById('results-section'),
    packageName: document.getElementById('package-name'),
    packageVersion: document.getElementById('package-version'),
    progressFill: document.getElementById('progress-fill'),
    progressText: document.getElementById('progress-text'),
    totalSymbols: document.getElementById('total-symbols'),
    documentedCount: document.getElementById('documented-count'),
    undocumentedCount: document.getElementById('undocumented-count'),
    undocumentedTotal: document.getElementById('undocumented-total'),
    documentedTotal: document.getElementById('documented-total'),
    undocumentedTbody: document.getElementById('undocumented-tbody'),
    documentedTbody: document.getElementById('documented-tbody'),
    undocumentedContainer: document.getElementById('undocumented-container')
};

// Initialize WASM
async function initializeApp() {
    try {
        console.log('Initializing WASM...');
        await init();
        state.wasmReady = true;
        console.log('WASM loaded successfully');
        elements.auditButton.disabled = false;
    } catch (error) {
        showError('Failed to load the application. Please refresh the page.');
        console.error('WASM initialization error:', error);
    }
}

// JSR Autocomplete
async function fetchAutocomplete(query) {
    if (query.length < 2) return [];

    try {
        const response = await fetch(`https://jsr.io/api/packages?query=${encodeURIComponent(query)}&limit=10`);
        const data = await response.json();
        return data.items || [];
    } catch (error) {
        console.error('Autocomplete fetch error:', error);
        return [];
    }
}

function setupAutocomplete() {
    elements.packageInput.addEventListener('input', async (e) => {
        const query = e.target.value.trim();

        clearTimeout(state.autocompleteTimeout);
        state.selectedIndex = -1;

        if (query.length < 2) {
            hideAutocomplete();
            return;
        }

        state.autocompleteTimeout = setTimeout(async () => {
            const results = await fetchAutocomplete(query);
            state.autocompleteResults = results;
            displayAutocomplete(results, query);
        }, 300);
    });

    elements.packageInput.addEventListener('keydown', (e) => {
        const dropdown = elements.autocompleteDropdown;
        if (dropdown.classList.contains('hidden')) return;

        const items = dropdown.querySelectorAll('.autocomplete-item');

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                state.selectedIndex = Math.min(state.selectedIndex + 1, items.length - 1);
                updateActiveItem(items);
                break;
            case 'ArrowUp':
                e.preventDefault();
                state.selectedIndex = Math.max(state.selectedIndex - 1, -1);
                updateActiveItem(items);
                break;
            case 'Enter':
                e.preventDefault();
                if (state.selectedIndex >= 0 && items[state.selectedIndex]) {
                    const packageName = items[state.selectedIndex].dataset.package;
                    selectPackage(packageName);
                } else {
                    auditPackage(elements.packageInput.value.trim());
                }
                break;
            case 'Escape':
                hideAutocomplete();
                break;
        }
    });

    // Click outside to close
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.input-wrapper')) {
            hideAutocomplete();
        }
    });
}

function updateActiveItem(items) {
    items.forEach((item, index) => {
        if (index === state.selectedIndex) {
            item.classList.add('active');
            item.scrollIntoView({ block: 'nearest' });
        } else {
            item.classList.remove('active');
        }
    });
}

function displayAutocomplete(results, query) {
    if (results.length === 0) {
        hideAutocomplete();
        return;
    }

    const dropdown = elements.autocompleteDropdown;
    dropdown.innerHTML = '';

    results.forEach((result, index) => {
        const item = document.createElement('div');
        item.className = 'autocomplete-item';
        const fullName = `@${result.scope}/${result.name}`;
        item.dataset.package = fullName;

        const nameDiv = document.createElement('div');
        nameDiv.className = 'autocomplete-name';
        nameDiv.textContent = fullName;

        item.appendChild(nameDiv);

        if (result.description) {
            const descDiv = document.createElement('div');
            descDiv.className = 'autocomplete-description';
            descDiv.textContent = result.description;
            item.appendChild(descDiv);
        }

        item.addEventListener('click', () => {
            selectPackage(fullName);
        });

        dropdown.appendChild(item);
    });

    dropdown.classList.remove('hidden');
}

function selectPackage(packageName) {
    elements.packageInput.value = packageName;
    hideAutocomplete();
    auditPackage(packageName);
}

function hideAutocomplete() {
    elements.autocompleteDropdown.classList.add('hidden');
    state.selectedIndex = -1;
}

// Package audit
async function auditPackage(packageSpec) {
    if (!state.wasmReady) {
        showError('Application is still loading. Please wait...');
        return;
    }

    if (!packageSpec) {
        showError('Please enter a package name');
        return;
    }

    console.log('Auditing package:', packageSpec);
    showLoading();
    hideError();
    hideResults();
    hideAutocomplete();

    try {
        const result = await audit_package(packageSpec);
        console.log('Audit result:', result);
        displayResults(result);
    } catch (error) {
        const errorMessage = error.toString().replace('Error: ', '').replace('RuntimeError: ', '');
        showError(`Failed to audit package: ${errorMessage}`);
        console.error('Audit error:', error);
    } finally {
        hideLoading();
    }
}

// Display results
function displayResults(result) {
    // Update package info
    elements.packageName.textContent = `@${result.package.scope}/${result.package.name}`;
    elements.packageVersion.textContent = result.package.version;

    // Update coverage stats
    const { coverage } = result;
    elements.totalSymbols.textContent = coverage.totalSymbols;
    elements.documentedCount.textContent = coverage.documentedSymbols;
    elements.undocumentedCount.textContent = coverage.undocumentedSymbols;

    // Update progress bar
    const percentage = coverage.percentage;
    const progressClass = getCoverageClass(percentage);

    elements.progressFill.style.width = `${percentage}%`;
    elements.progressFill.className = `progress-fill ${progressClass}`;

    elements.progressText.textContent = `${percentage}%`;
    elements.progressText.className = `progress-text ${progressClass}`;

    // Populate tables
    populateSymbolTable(elements.undocumentedTbody, result.undocumented);
    populateSymbolTable(elements.documentedTbody, result.documented);

    elements.undocumentedTotal.textContent = result.undocumented.length;
    elements.documentedTotal.textContent = result.documented.length;

    // Show/hide undocumented section
    if (result.undocumented.length === 0) {
        elements.undocumentedContainer.classList.add('hidden');
    } else {
        elements.undocumentedContainer.classList.remove('hidden');
    }

    showResults();

    // Scroll to results
    elements.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function populateSymbolTable(tbody, symbols) {
    tbody.innerHTML = '';

    if (symbols.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="4" style="text-align: center; color: var(--color-text-secondary);">No symbols</td>';
        tbody.appendChild(row);
        return;
    }

    symbols.forEach(symbol => {
        const row = document.createElement('tr');

        const moduleCell = document.createElement('td');
        moduleCell.textContent = symbol.module;
        row.appendChild(moduleCell);

        const nameCell = document.createElement('td');
        const nameStrong = document.createElement('strong');
        nameStrong.textContent = symbol.name;
        nameCell.appendChild(nameStrong);
        row.appendChild(nameCell);

        const kindCell = document.createElement('td');
        const kindBadge = document.createElement('span');
        kindBadge.className = 'kind-badge';
        kindBadge.textContent = symbol.kind;
        kindCell.appendChild(kindBadge);
        row.appendChild(kindCell);

        const locationCell = document.createElement('td');
        const locationCode = document.createElement('code');
        locationCode.textContent = symbol.location;
        locationCell.appendChild(locationCode);
        row.appendChild(locationCell);

        tbody.appendChild(row);
    });
}

function getCoverageClass(percentage) {
    if (percentage >= 90) return 'high';
    if (percentage >= 70) return 'medium';
    return 'low';
}

// UI helpers
function showLoading() {
    elements.loading.classList.remove('hidden');
    elements.auditButton.disabled = true;
}

function hideLoading() {
    elements.loading.classList.add('hidden');
    elements.auditButton.disabled = false;
}

function showError(message) {
    elements.error.textContent = message;
    elements.error.classList.remove('hidden');
}

function hideError() {
    elements.error.classList.add('hidden');
}

function showResults() {
    elements.resultsSection.classList.remove('hidden');
}

function hideResults() {
    elements.resultsSection.classList.add('hidden');
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing app...');

    // Disable button until WASM is ready
    elements.auditButton.disabled = true;

    initializeApp();
    setupAutocomplete();

    elements.auditButton.addEventListener('click', () => {
        const packageSpec = elements.packageInput.value.trim();
        auditPackage(packageSpec);
    });

    elements.packageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.target.closest('.autocomplete-item')) {
            const packageSpec = e.target.value.trim();
            auditPackage(packageSpec);
        }
    });
});
