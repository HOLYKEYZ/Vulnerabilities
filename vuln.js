// vulnerabilities-expanded.js

// 1. Cross-Site Scripting (XSS)
const userInput = "<img src=x onerror=alert('XSS')>";
document.getElementById("output").innerHTML = userInput;

// 2. Insecure eval()
const code = "alert('This is unsafe')";
eval(code);

// 3. Insecure document.write()
const htmlContent = "<h1>Welcome</h1>";
document.write(htmlContent);

// 4. Open Redirect
const params = new URLSearchParams(window.location.search);
const redirectTo = params.get("next");
window.location.href = redirectTo;

// 5. Insecure Cookie Handling
document.cookie = "sessionId=abc123";

// 6. Local Storage Misuse
localStorage.setItem("authToken", "super-secret-token");

// 7. Insecure Fetch to HTTP
fetch("http://untrusted.example.com/api", {
  method: "POST",
  body: JSON.stringify({ data: "test" }),
  headers: { "Content-Type": "application/json" }
});

// 8. Hardcoded Secrets
const API_KEY = "12345-ABCDE-SECRET";

// 9. DOM Injection via innerHTML
const comment = "<script>alert('Injected!')</script>";
document.getElementById("comments").innerHTML = comment;

// 10. Dangerous setTimeout with eval
setTimeout("alert('Delayed XSS')", 1000);

// 11. Insecure jQuery HTML injection
$('#container').html(userInput);

// 12. Insecure Function Constructor
const dynamicFunc = new Function("console.log('Executed dynamic code');");
dynamicFunc();

// 13. Prototype Pollution
let payload = JSON.parse('{ "__proto__": { "admin": true } }');
Object.assign({}, payload);

// 14. Clickjacking vulnerability (no X-Frame-Options)
document.write('<iframe src="http://malicious-site.com"></iframe>');

// 15. Insecure WebSocket
const socket = new WebSocket("ws://untrusted.example.com/socket");

// 16. Insecure JSONP usage
const script = document.createElement("script");
script.src = "http://evil.com/jsonp?callback=stealData";
document.head.appendChild(script);

// 17. Insecure file upload (simulated)
function uploadFile(file) {
  fetch("/upload", {
    method: "POST",
    body: file
  });
}

// 18. Insecure CORS configuration (simulated)
fetch("http://api.example.com/data", {
  method: "GET",
  mode: "no-cors"
});

// 19. Insecure use of innerText (can be manipulated)
const unsafeText = "<script>alert('innerText XSS')</script>";
document.getElementById("text").innerText = unsafeText;

// 20. Insecure iframe injection
const iframe = document.createElement("iframe");
iframe.src = userInput;
document.body.appendChild(iframe);

