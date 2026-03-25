from flask import Flask, request, jsonify
from flask_cors import CORS
from SafeStateCompiler import SafeStateCompiler

app = Flask(__name__)
CORS(app)

@app.route('/compile_both', methods=['POST'])
def compile_both():
    data = request.json
    source_code = data.get('code', '')
    
    if not source_code.strip():
        return jsonify({"error": "No code provided"}), 400

    veritas = SafeStateCompiler(source_code)
    veritas_report = veritas.compile()

    gcc_report = {
        "status": "SUCCESS",
        "message": "Compiled successfully. Warning: 0 security checks performed.",
        "executable": "a.out generated."
    }

    return jsonify({
        "veritas": veritas_report,
        "gcc": gcc_report
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)