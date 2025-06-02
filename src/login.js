// src/login.js
document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const role = sessionStorage.getItem("selectedRole") || "student";

  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    
    const email = document.querySelector('input[type="email"]').value.trim();
    const password = document.querySelector('input[type="password"]').value.trim();

    if (!email || !password) {
      alert("❌ Please fill all fields.");
      return;
    }

    try {
      // Call Tauri backend
      const result = await window.__TAURI__.invoke("tauri_login", {
        payload: {
          email,
          password,
          role
        }
      });

      if (result.success && result.user) {
        // Store user data in sessionStorage
        sessionStorage.setItem("currentUser", JSON.stringify(result.user));
        sessionStorage.setItem("authToken", result.token || "");
        
        alert(`✅ Welcome, ${result.user.firstname}!`);
        
        // Redirect based on role
        if (role === "student") {
          window.location.href = "marking.html";
        } else {
          window.location.href = "dash.html";
        }
      } else {
        alert("❌ " + result.message);
      }
    } catch (error) {
      console.error("Login error:", error);
      alert("❌ Login failed: " + error);
    }
  });
});