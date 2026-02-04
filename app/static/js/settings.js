/**
 * Sentinels Settings Page
 * Handles data export and database management
 */

document.addEventListener('DOMContentLoaded', () => {
    const exportBtn = document.getElementById('exportBtn');
    const clearDatabaseBtn = document.getElementById('clearDatabaseBtn');

    // ===== Export Threat Report =====
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            // Show loading state
            exportBtn.disabled = true;
            exportBtn.innerHTML = `
                <span class="material-symbols-outlined text-sm animate-spin">sync</span>
                Generating...
            `;

            // Trigger download by redirecting to export endpoint
            window.location.href = '/api/threats/export';

            // Reset button after a short delay
            setTimeout(() => {
                exportBtn.disabled = false;
                exportBtn.innerHTML = `
                    <span class="material-symbols-outlined text-sm">description</span>
                    Download Threat Report (CSV)
                `;
            }, 2000);
        });
    }

    // ===== Clear Database =====
    if (clearDatabaseBtn) {
        clearDatabaseBtn.addEventListener('click', async () => {
            const confirmed = confirm(
                'Are you sure you want to delete ALL threat records?\n\n' +
                'This action cannot be undone. Consider exporting your data first.'
            );

            if (!confirmed) return;

            // Double confirm for extra safety
            const doubleConfirm = confirm(
                '⚠️ FINAL WARNING ⚠️\n\n' +
                'All threat logs will be permanently deleted.\n\n' +
                'Click OK to proceed with deletion.'
            );

            if (!doubleConfirm) return;

            // Show loading state
            clearDatabaseBtn.disabled = true;
            clearDatabaseBtn.innerHTML = `
                <span class="material-symbols-outlined text-sm animate-spin">sync</span>
                Clearing...
            `;

            try {
                const response = await fetch('/api/threats/clear', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                const data = await response.json();

                if (data.success) {
                    // Show success toast
                    showToast(`Successfully deleted ${data.deleted_count} threat records`, 'success');
                } else {
                    showToast('Failed to clear database', 'error');
                }
            } catch (error) {
                console.error('Error clearing database:', error);
                showToast('Error: Could not connect to server', 'error');
            } finally {
                // Reset button
                clearDatabaseBtn.disabled = false;
                clearDatabaseBtn.innerHTML = `
                    <span class="material-symbols-outlined text-sm">delete_forever</span>
                    Clear Threat Database
                `;
            }
        });
    }

    // ===== Toast Notification =====
    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 transition-all transform ${type === 'success' ? 'bg-primary text-black' : 'bg-danger text-white'
            }`;
        toast.innerHTML = `<span class="font-bold">${message}</span>`;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    console.log('[Settings] Page initialized');
});
