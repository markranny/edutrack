// src/signup.js
document.addEventListener("DOMContentLoaded", function () {
  const signupForm = document.getElementById("signupForm");
  const role = sessionStorage.getItem("selectedRole") || "student";

  signupForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const firstname = document.getElementById("firstname").value.trim();
    const lastname = document.getElementById("lastname").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();

    // Validation
    if (password !== confirmPassword) {
      alert("❌ Password and Confirm Password do not match.");
      return;
    }
    if (!firstname || !lastname || !email || !password) {
      alert("❌ Please fill all required fields.");
      return;
    }
    if (password.length < 6) {
      alert("❌ Password must be at least 6 characters long.");
      return;
    }

    try {
      // Call Tauri backend
      const result = await window.__TAURI__.invoke("tauri_signup", {
        payload: {
          firstname,
          lastname,
          email,
          password,
          role
        }
      });

      if (result.success) {
        alert("✅ Registration successful!");
        window.location.href = "login.html";
      } else {
        alert("❌ " + result.message);
      }
    } catch (error) {
      console.error("Signup error:", error);
      alert("❌ Signup failed: " + error);
    }
  });
});