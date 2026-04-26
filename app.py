from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

# Ensure static and templates folders exist
os.makedirs('static', exist_ok=True)
os.makedirs('templates', exist_ok=True)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'POST')
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/compile', methods=['POST'])
def compile_code():
    code = request.json.get('code', '')
    if not code.strip():
        return jsonify({'error': 'No code provided.'})

    # Save code to a temporary C file
    temp_file = 'temp_code.c'
    with open(temp_file, 'w') as f:
        f.write(code)

    # 1. Compile with standard GCC
    try:
        # We use -o temp.exe to fully compile it and see if it passes
        gcc_process = subprocess.run(
            ['gcc', temp_file, '-o', 'temp_code.exe'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if gcc_process.returncode == 0:
            gcc_output = '[ SUCCESS ] Code compiled successfully using standard GCC.\n\n' + gcc_process.stdout
            if gcc_process.stderr: # GCC warnings often go to stderr even on success
                gcc_output += "\n--- Warnings ---\n" + gcc_process.stderr
        else:
            gcc_output = '[ ERROR ] GCC Compilation Failed:\n\n' + gcc_process.stderr
    except Exception as e:
        gcc_output = f'[ ERROR ] Failed to run GCC: {str(e)}'

    # 2. Compile with Mini Compiler
    try:
        mini_process = subprocess.run(
            ['python', 'veritas_compiler.py', temp_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        mini_output = mini_process.stdout + '\n' + mini_process.stderr
        if 'VULNERABILITY:' in mini_output or mini_process.returncode != 0:
            mini_output = '[ ERROR ] Veritas Compiler detected an issue:\n\n' + mini_output
        else:
            mini_output = '[ SUCCESS ] Veritas Compiler passed all checks!\n\n' + mini_output
    except Exception as e:
        mini_output = f'[ ERROR ] Failed to run Mini Compiler: {str(e)}'

    # Cleanup temp files
    try:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    except Exception: pass
    
    try:
        if os.path.exists('temp_code.exe'):
            os.remove('temp_code.exe')
    except Exception: pass

    return jsonify({
        'gcc': gcc_output,
        'mini': mini_output
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
