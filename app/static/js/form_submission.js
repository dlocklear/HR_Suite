document.addEventListener("DOMContentLoaded", function() {
    const form = document.querySelector("#evaluationForm");
    const flashMessage = document.createElement("div");
    flashMessage.classList.add("flash-message");
    document.body.prepend(flashMessage);

    form.addEventListener("submit", async function(event) {
        event.preventDefault();
        flashMessage.textContent = "";

        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());

        try {
            const response = await fetch(form.action, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                flashMessage.textContent = "Evaluation submitted successfully.";
                flashMessage.classList.add("success");
                form.reset();
            } else {
                throw new Error("Error submitting evaluation");
            }
        } catch (error) {
            flashMessage.textContent = "An error occurred while submitting the evaluation.";
            flashMessage.classList.add("error");
        }

        setTimeout(() => {
            flashMessage.textContent = "";
            flashMessage.classList.remove("success", "error");
        }, 5000);
    });
});
