let cCode = "";

//Handle File Selection
document.getElementById('file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('filename').innerText = file.name;
        const reader = new FileReader();
        reader.onload = (ev) => {
            cCode = ev.target.result;
            document.getElementById('code-preview').innerText = cCode;
            document.getElementById('run-btn').disabled = false;
        };
        reader.readAsText(file);
    }
});

//Run the Pipeline
async function runPipeline() {
    
    const gOut = document.getElementById('gcc-out');
    const vOut = document.getElementById('veritas-out');
    const gMsg = document.getElementById('gcc-msg');
    const vMsg = document.getElementById('veritas-msg');

    gMsg.innerText = "Compiling with GCC...";
    vMsg.innerText = "Scanning AST...";
    gOut.innerHTML = "> Processing...";
    vOut.innerHTML = "<p>Analyzing...</p>";

    try {
        const res = await fetch('http://localhost:5000/compile_both', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: cCode })
        });

        if (!res.ok) throw new Error("Backend server error");

        const data = await res.json();

        gMsg.innerText = `[${data.gcc.status}] ${data.gcc.message}`;
        gOut.innerHTML = `> gcc input.c<br>> status: 0<br>> ${data.gcc.executable}`;

        vMsg.innerText = `[${data.veritas.status}] ${data.veritas.message}`;

        if (data.veritas.status === "HALTED") {
            
            vOut.innerHTML = data.veritas.vulnerabilities.map(v => 
                `<div style="background: #fff5f5; border-left: 3px solid #f87171; padding: 10px; margin-bottom: 8px; border-radius: 4px; font-size: 0.85em; text-align: left;">
                    <strong style="color: #991b1b;">Line ${v.line}:</strong> ${v.issue}<br>
                    <small style="color: #475569;">${v.fix}</small>
                </div>`
            ).join('');
        } else {
            vOut.innerHTML = "<p style='color:#166534; font-weight:bold; text-align: center;'>✅ AST Verified: No vulnerabilities found.</p>";
        }

    } catch (err) {
        console.error("Fetch Error:", err);
        vMsg.innerText = "[ERROR] Connection Failed";
        vOut.innerHTML = "<span style='color:red;'>Could not connect to backend. Is app.py running?</span>";
    }
}