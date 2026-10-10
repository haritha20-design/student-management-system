
document.addEventListener("DOMContentLoaded", function () {

    // Show / Hide Password
    const toggleButtons = document.querySelectorAll(
        "[data-toggle-password]"
    );

    toggleButtons.forEach(function (button) {

        button.addEventListener("click", function () {

            const inputId = button.getAttribute(
                "data-toggle-password"
            );

            const passwordInput = document.getElementById(inputId);

            if (!passwordInput) return;

            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                button.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
            } else {
                passwordInput.type = "password";
                button.innerHTML = '<i class="fa-solid fa-eye"></i>';
            }

        });

    });

    // Confirm Password Validation
    const registerForm = document.querySelector(
        'form[action*="register"]'
    );

    if (registerForm) {

        registerForm.addEventListener("submit", function (event) {

            const password = document.getElementById("password");
            const confirmPassword = document.getElementById(
                "confirm_password"
            );

            if (
                password &&
                confirmPassword &&
                password.value !== confirmPassword.value
            ) {
                event.preventDefault();

                alert("Password and Confirm Password do not match!");
                confirmPassword.focus();
            }

        });

    }

});
