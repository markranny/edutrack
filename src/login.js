// src/login.js
document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const emailInput = document.getElementById("emailInput");
  const passwordInput = document.getElementById("passwordInput");
  const role = sessionStorage.getItem("selectedRole") || "student";

  // Wait for Tauri to be ready
  function waitForTauri() {
    return new Promise((resolve) => {
      const checkTauri = () => {
        if (window.__TAURI__ && window.__TAURI__.invoke) {
          resolve();
        } else {
          setTimeout(checkTauri, 100);
        }
      };
      checkTauri();
    });
  }

  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    
    const email = emailInput.value.trim();
    const password = passwordInput.value.trim();

    if (!email || !password) {
      alert("❌ Please fill all fields.");
      return;
    }

    try {
      // Wait for Tauri to be ready
      await waitForTauri();
      
      console.log("Attempting login with:", { email, role });
      
      // Call Tauri backend
      const result = await window.__TAURI__.invoke("tauri_login", {
        payload: {
          email,
          password,
          role
        }
      });

      console.log("Login result:", result);

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
        alert("❌ " + (result.message || "Login failed"));
      }
    } catch (error) {
      console.error("Login error:", error);
      alert("❌ Login failed: " + error);
    }
  });
});