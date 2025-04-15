// Custom JavaScript functionality for the check file application

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // File size validation
    const fileInput = document.getElementById('file');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const maxSize = 16 * 1024 * 1024; // 16MB in bytes
            
            if (this.files[0] && this.files[0].size > maxSize) {
                alert('Error: File size exceeds the maximum allowed size (16MB).');
                this.value = ''; // Clear the file input
            }
            
            // Display file name selected
            if (this.files[0]) {
                const fileName = this.files[0].name;
                const fileSize = Math.round(this.files[0].size / 1024); // Size in KB
                
                // You could update a label or display with this information
                console.log(`Selected file: ${fileName} (${fileSize} KB)`);
            }
        });
    }
    
    // Add animation to results page
    const resultsCard = document.querySelector('.card');
    if (resultsCard && window.location.pathname.includes('/results')) {
        resultsCard.classList.add('scan-complete');
    }
    
    // Add tooltips
    const tooltips = document.querySelectorAll('[title]');
    tooltips.forEach(tooltip => {
        // Initialize tooltips with Bootstrap (if using Bootstrap)
        // This requires Bootstrap's JavaScript to be loaded
        if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
            new bootstrap.Tooltip(tooltip);
        }
    });
});