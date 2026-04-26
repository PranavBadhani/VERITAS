const fileInput = document.getElementById('file-upload');
const codeEditor = document.getElementById('code-editor');
const compileBtn = document.getElementById('compile-btn');
const gccOutput = document.getElementById('gcc-output');
const miniOutput = document.getElementById('mini-output');

const lineNumbers = document.getElementById('line-numbers');

function updateLineNumbers() {
    const lines = codeEditor.value.split('\n').length;
    lineNumbers.innerHTML = Array(Math.max(1, lines)).fill(0).map((_, i) => i + 1).join('<br>');
}

codeEditor.addEventListener('input', updateLineNumbers);
codeEditor.addEventListener('scroll', () => {
    lineNumbers.scrollTop = codeEditor.scrollTop;
});

// Handle File Upload
fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            codeEditor.value = e.target.result;
            updateLineNumbers();
        };
        reader.readAsText(file);
    }
});

// Handle Compilation
compileBtn.addEventListener('click', async () => {
    const code = codeEditor.value;
    if (!code.trim()) {
        alert("Please provide some C code or upload a file first.");
        return;
    }

    // Set loading state
    compileBtn.disabled = true;
    compileBtn.innerText = "Compiling...";
    gccOutput.innerText = "Running GCC...";
    miniOutput.innerText = "Running Veritas Compiler...";

    try {
        const response = await fetch('http://127.0.0.1:5000/compile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();
        if (data.error) {
            alert(data.error);
        } else {
            gccOutput.innerText = data.gcc;
            miniOutput.innerText = data.mini;

            gccOutput.style.color = data.gcc.includes('[ ERROR ]') ? 'var(--error)' : '#34d399';
            miniOutput.style.color = data.mini.includes('[ ERROR ]') ? 'var(--error)' : '#60a5fa';
        }
    } catch (error) {
        gccOutput.innerText = "Error establishing connection.";
        miniOutput.innerText = "Error establishing connection.";
    } finally {
        compileBtn.disabled = false;
        compileBtn.innerText = "Compile Code";
    }
});
