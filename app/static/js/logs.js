/**
 * Sentinels - Threat Logs Page JavaScript
 */

// Delete a single threat
async function deleteLog(id) {
    if (!confirm('Delete this threat record?')) return;

    try {
        const response = await fetch(`/api/threats/delete/${id}`, { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            // Remove row from table
            const row = document.getElementById(`row-${id}`);
            if (row) {
                row.remove();
                updateCount(-1);
            }
        } else {
            alert('Failed to delete threat');
        }
    } catch (error) {
        console.error('Delete error:', error);
        alert('Error deleting threat');
    }
}

// Update the count display
function updateCount(delta) {
    const countEl = document.getElementById('totalCount');
    const current = parseInt(countEl.textContent) || 0;
    const newCount = Math.max(0, current + delta);
    countEl.textContent = newCount;

    // Show empty state if no threats left
    if (newCount === 0) {
        const tbody = document.getElementById('logsTableBody');
        tbody.innerHTML = `
            <tr id="emptyState">
                <td colspan="8" class="px-6 py-16 text-center text-gray-500">
                    <span class="material-symbols-outlined text-5xl mb-3 block text-primary">verified_user</span>
                    <p class="text-lg font-medium text-gray-400">No threats detected</p>
                    <p class="text-sm">Your network is secure. Threats will appear here when detected.</p>
                </td>
            </tr>
        `;
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Clear all history button
    const clearBtn = document.getElementById('clearHistoryBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to delete ALL threat history? This cannot be undone.')) return;

            try {
                const response = await fetch('/api/threats/clear', { method: 'POST' });
                const data = await response.json();

                if (data.success) {
                    location.reload();
                } else {
                    alert('Failed to clear history');
                }
            } catch (error) {
                console.error('Clear error:', error);
                alert('Error clearing history');
            }
        });
    }

    // Event delegation for delete buttons
    document.addEventListener('click', (e) => {
        const deleteBtn = e.target.closest('.delete-btn');
        if (deleteBtn) {
            const id = deleteBtn.dataset.id;
            if (id) {
                deleteLog(id);
            }
        }
    });

    console.log('[Sentinels] Logs page initialized');
});
