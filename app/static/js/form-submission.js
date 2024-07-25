document.getElementById('evaluationForm').addEventListener('submit', function(event) {
    event.preventDefault();
    fetch(this.action, {
        method: this.method,
        body: new FormData(this),
    }).then(response => response.json()).then(data => {
        if (data.success) {
            document.getElementById('notification').innerHTML = 'Evaluation submitted successfully!';
            document.getElementById('notification').style.display = 'block';
            this.reset();
        } else {
            document.getElementById('notification').innerHTML = 'Failed to submit evaluation.';
            document.getElementById('notification').style.display = 'block';
        }
    }).catch(error => {
        console.error('Error:', error);
        document.getElementById('notification').innerHTML = 'An error occurred.';
        document.getElementById('notification').style.display = 'block';
    });
});
