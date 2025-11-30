// vulnerabilities.ts

// 1. DOM-based XSS
const userInput = location.hash.substring(1);
document.getElementById("output")!.innerHTML = userInput;

// 2. Insecure eval()
const code = "console.log('Executed unsafe code')";
eval(code);

// 3. Insecure innerHTML assignment
const comment = "<img src='x' onerror='alert(\"XSS\")'>";
document.getElementById("comments")!.innerHTML = comment;

// 4. Open Redirect
const params = new URLSearchParams(window.location.search);
const redirectTo = params.get("redirect");
if (redirectTo) {
  window.location.href = redirectTo;
}

// 5. Insecure localStorage usage
localStorage.setItem("authToken", "super-secret-token");

// 6. Hardcoded API Key
const API_KEY = "sk_test_1234567890abcdef";

// 7. Insecure fetch to HTTP
fetch("http://insecure-api.example.com/data", {
  method: "POST",
  body: JSON.stringify({ data: "test" }),
  headers: { "Content-Type": "application/json" }
});

// 8. Insecure use of setTimeout with string
setTimeout("alert('This is unsafe')", 1000);

// 9. Insecure use of Function constructor
const dynamicFunction = new Function("console.log('Dynamic code execution');");
dynamicFunction();

// 10. Clickjacking vulnerability (no frame busting)
document.write('<iframe src="http://malicious-site.com"></iframe>');

// 11. Insecure cookie handling
document.cookie = "sessionId=abc123";

// 12. Insecure WebSocket
const socket = new WebSocket("ws://untrusted.example.com/socket");

// 13. Insecure JSONP usage
const script = document.createElement("script");
script.src = "http://evil.com/jsonp?callback=stealData";
document.body.appendChild(script);

// 14. Insecure file download
function downloadFile(url: string) {
  fetch(url)
    .then(res => res.blob())
    .then(blob => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "file.txt";
      a.click();
    });
}
downloadFile("http://malicious-site.com/file.txt");

// 15. Insecure regex (ReDoS)
const userRegex = new RegExp("^(" + "a+".repeat(10000) + ")+$");
userRegex.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!");

// 16. Insecure deserialization (simulated)
const unsafeJSON = '{"__proto__":{"admin":true}}';
const obj = JSON.parse(unsafeJSON);
console.log((obj as any).admin);

// 17. Insecure innerText usage
const unsafeText = "<script>alert('XSS via innerText')</script>";
document.getElementById("text")!.innerText = unsafeText;

// 18. Insecure redirect via hash
if (location.hash.startsWith("#/redirect=")) {
  const target = location.hash.replace("#/redirect=", "");
  window.location.href = target;
}