
import re
import sys
import os
from typing import List, Dict, Any

# ==========================================
# STAGE 1: LEXICAL ANALYSIS
# ==========================================
class Token:
    def __init__(self, type_, value, line):
        self.type = type_
        self.value = value
        self.line = line

class Lexer:
    TOKENS = [
        ('PREPROC',         r'#.*'),
        ('COMMENT',         r'//.*|/\*[\s\S]*?\*/'),
        ('STRING',          r'"(?:\\.|[^"\\])*"'),
        ('UNCLOSED_STRING', r'"(?:\\.|[^"\\])*\n'),
        ('NUMBER',          r'\d+'),
        ('KEYWORD',     r'\b(int|void|return|malloc|free|printf|gets|strcpy|memset)\b'),
        ('IDENTIFIER',  r'[a-zA-Z_]\w*'),
        ('OP',          r'[+\-*/=]'),
        ('PUNCT',       r'[(){},;\[\]]'),
        ('NEWLINE',     r'\n'),
        ('SKIP',        r'[ \t]+'),
        ('MISMATCH',    r'.'),
    ]

    @classmethod
    def tokenize(cls, code: str) -> List[Token]:
        tokens = []
        line_num = 1
        pos = 0
        regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in cls.TOKENS)
        for mo in re.finditer(regex, code):
            kind = mo.lastgroup
            value = mo.group()
            if kind == 'NEWLINE': line_num += 1
            elif kind == 'COMMENT' or kind == 'PREPROC': line_num += value.count('\n')
            elif kind == 'SKIP': continue
            elif kind == 'UNCLOSED_STRING':
                raise SyntaxError(f"Lexical error at line {line_num}: Unclosed string literal")
            elif kind == 'MISMATCH': 
                raise SyntaxError(f"Lexical error at line {line_num}: Unexpected or invalid character '{value}'")
            else:
                tokens.append(Token(kind, value, line_num))
        tokens.append(Token('EOF', '', line_num))
        return tokens

# ==========================================
# STAGE 2: SYNTAX ANALYSIS (PARSING)
# ==========================================
class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def consume(self, expected_type=None, expected_val=None):
        tok = self.tokens[self.pos]
        if expected_type and tok.type != expected_type:
            raise SyntaxError(f"Line {tok.line}: Expected {expected_type}, got {tok.type}")
        if expected_val and tok.value != expected_val:
            raise SyntaxError(f"Line {tok.line}: Expected '{expected_val}', got '{tok.value}'")
        self.pos += 1
        return tok

    def peek(self):
        return self.tokens[self.pos]

    def parse(self) -> List[Dict]:
        ast = []
        while self.peek().type != 'EOF':
            ast.append(self.parse_statement())
        return ast

    def parse_statement(self):
        tok = self.peek()
        # Handle int x = 10;
        if tok.type == 'KEYWORD' and tok.value == 'int':
            self.consume()
            name = self.consume('IDENTIFIER').value
            if self.peek().value == '=':
                line = self.peek().line
                self.consume(expected_val='=')
                expr = self.parse_expr()
                self.consume(expected_val=';')
                return {'node': 'Assign', 'target': name, 'val': expr, 'line': line}
            elif self.peek().value == '(':
                # E.g. int main() 
                self.consume(expected_val='(')
                self.consume(expected_val=')')
                return {'node': 'FuncDef', 'name': name, 'line': tok.line}
            self.consume(expected_val=';')
            return {'node': 'VarDecl', 'name': name, 'line': tok.line}
            
        # Handle Function calls: printf(...);
        elif tok.type == 'KEYWORD' or tok.type == 'IDENTIFIER':
            name_tok = self.consume()
            if self.peek().value == '(':
                self.consume(expected_val='(')
                args = []
                if self.peek().value != ')':
                    while True:
                        args.append(self.parse_expr())
                        if self.peek().value == ',': self.consume(expected_val=',')
                        else: break
                self.consume(expected_val=')')
                self.consume(expected_val=';')
                return {'node': 'FuncCall', 'func': name_tok.value, 'args': args, 'line': name_tok.line}
            elif self.peek().value == '=':
                line = self.peek().line
                self.consume(expected_val='=')
                expr = self.parse_expr()
                self.consume(expected_val=';')
                return {'node': 'Assign', 'target': name_tok.value, 'val': expr, 'line': line}
                
        # Basic fallback for block wrappers (ignoring for this mini syntax but preventing crashes)
        elif tok.value in ['{', '}']:
            self.consume()
            return {'node': 'Block', 'val': tok.value, 'line': tok.line}
            
        raise SyntaxError(f"Line {tok.line}: Unexpected statement starting with '{tok.value}'")

    def parse_expr(self):
        # Extremely simplified expression parser (deals with single literal, var, or math like 'a + b')
        left_tok = self.consume()
        left = {'node': 'Literal', 'val': left_tok.value, 'type': left_tok.type}
        
        if self.peek().type == 'OP' and self.peek().value != '=':
            op = self.consume().value
            right_tok = self.consume()
            right = {'node': 'Literal', 'val': right_tok.value, 'type': right_tok.type}
            return {'node': 'MathOp', 'op': op, 'left': left, 'right': right}
        return left

# ==========================================
# STAGE 3: SEMANTIC ANALYSIS & VULNERABILITIES
# ==========================================
class SemanticAnalyzer:
    def __init__(self):
        self.freed_vars = set()
        self.sensitive_vars = set()
        self.scrubbed_vars = set()
        self.var_values = {}
        self.vulnerabilities = []

    def analyze(self, ast: List[Dict]):
        for stmt in ast:
            self.visit(stmt)
            
        # End of scope check for scrub vulnerabilities
        unscrubbed = self.sensitive_vars - self.scrubbed_vars
        if unscrubbed:
            self.vulnerabilities.append("VULNERABILITY: Memory Scrubbing omission (can cause sensitive data like passwords to be retrieved by attackers)\nLINE: End of Scope\nSOLUTION: Be extremely sure to `memset()` all securely sensitive variables before they exit the scope!")
            
        if len(self.vulnerabilities) > 0:
            separator = "\n\n======================================================\n\n"
            raise Exception(separator.join(self.vulnerabilities))

    def visit(self, node: Dict):
        if node['node'] == 'Assign':
            if node['val'].get('node') == 'Literal' and node['val'].get('type') == 'NUMBER':
                self.var_values[node['target']] = int(node['val']['val'])
            
            # Check if name contains secret
            if 'secret' in node['target'] or 'password' in node['target']:
                self.sensitive_vars.add(node['target'])
            
            # Use-After-Free: if right-hand side is a freed variable
            if node['val'].get('type') == 'IDENTIFIER' and node['val']['val'] in self.freed_vars:
                if node['val']['val'] not in str(self.vulnerabilities):
                    self.vulnerabilities.append(f"VULNERABILITY: Use-After-Free (can cause memory corruption and arbitrary code execution)\nLINE: {node['line']}\nSOLUTION: Ensure you do not reference memory after it has been freed.")
                
            self.visit_expr(node['val'])
            
        elif node['node'] == 'FuncCall':
            func = node['func']
            args = node['args']
            
            # Use-After-Free: if argument was freed, raise an error
            for arg in args:
                if arg.get('type') == 'IDENTIFIER' and arg['val'] in self.freed_vars:
                    if arg['val'] not in str(self.vulnerabilities):
                        self.vulnerabilities.append(f"VULNERABILITY: Use-After-Free (can cause memory corruption and arbitrary code execution)\nLINE: {node['line']}\nSOLUTION: Do not pass freed variables as function arguments.")

            if func == 'gets':
                self.vulnerabilities.append(f"VULNERABILITY: Buffer Overflow via `gets` (can allow attackers to overwrite adjacent memory and execute arbitrary code)\nLINE: {node['line']}\nSOLUTION: Use `fgets()` instead of `gets()` which natively enforces bounds checking.")
            elif func == 'strcpy':
                self.vulnerabilities.append(f"VULNERABILITY: Buffer Overflow via `strcpy` (can allow attackers to overwrite adjacent memory and execute arbitrary code)\nLINE: {node['line']}\nSOLUTION: Use `strncpy()` instead to cap the write size and prevent overflows.")
            elif func == 'printf':
                if args and args[0].get('type') != 'STRING':
                    self.vulnerabilities.append(f"VULNERABILITY: Format String error (can allow attackers to read/write arbitrary memory locations via %x and %n)\nLINE: {node['line']}\nSOLUTION: Ensure the first argument to printf is a strict string literal (e.g. `\"%s\"`), not a variable.")
            elif func == 'free':
                if args and args[0].get('type') == 'IDENTIFIER':
                    var_name = args[0]['val']
                    if var_name in self.sensitive_vars and var_name not in self.scrubbed_vars:
                        self.vulnerabilities.append(f"VULNERABILITY: Memory Scrubbing omission (can cause sensitive data like passwords to be retrieved by attackers)\nLINE: {node['line']}\nSOLUTION: Call `memset()` to explicitly securely wipe sensitive variable memory before freeing.")
                    self.freed_vars.add(var_name)
            elif func == 'memset':
                if args and args[0].get('type') == 'IDENTIFIER':
                    self.scrubbed_vars.add(args[0]['val'])
                    
    def visit_expr(self, expr: Dict):
        # Integer overflow check
        if expr.get('node') == 'MathOp':
            left = expr.get('left', {})
            right = expr.get('right', {})
            
            l_val = int(left['val']) if left.get('type') == 'NUMBER' else self.var_values.get(left.get('val'))
            r_val = int(right['val']) if right.get('type') == 'NUMBER' else self.var_values.get(right.get('val'))
            
            if l_val is not None and r_val is not None:
                res = l_val + r_val if expr['op'] == '+' else 0
                if res > 2147483647:
                    self.vulnerabilities.append(f"VULNERABILITY: Integer Overflow (can cause numeric logic to silently wrap past the 32-bit limit leading to buffer overflows elsewhere)\nLINE: End of Scope\nSOLUTION: Validate integer parameters against INT_MAX before arbitrary addition.")

# ==========================================
# STAGE 4: INTERMEDIATE REPRESENTATION (IR)
# ==========================================
def generate_ir(ast: List[Dict]) -> List[str]:
    ir = []
    temp_count = 0
    for stmt in ast:
        if stmt['node'] == 'Assign':
            val = stmt['val']
            if val['node'] == 'Literal':
                ir.append(f"ASSIGN {stmt['target']} {val['val']}")
            elif val['node'] == 'MathOp':
                temp_count += 1
                t = f"t{temp_count}"
                ir.append(f"{val['op']} {val['left']['val']} {val['right']['val']} {t}")
                ir.append(f"ASSIGN {stmt['target']} {t}")
        elif stmt['node'] == 'FuncCall':
            for arg in stmt['args']:
                ir.append(f"PARAM {arg['val']}")
            ir.append(f"CALL {stmt['func']} {len(stmt['args'])}")
    return ir

# ==========================================
# STAGE 5: OPTIMIZATION
# ==========================================
def optimize_ir(ir: List[str]) -> List[str]:
    optimized = []
    for line in ir:
        parts = line.split()
        if len(parts) == 4 and parts[0] == '+':
            # Constant Folding if possible
            try:
                res = int(parts[1]) + int(parts[2])
                optimized.append(f"MATH_CONST_FOLD {res} {parts[3]}")
                continue
            except ValueError: pass
        optimized.append(line)
    return optimized

# ==========================================
# STAGE 6: TARGET CODE GENERATION
# ==========================================
def generate_assembly(ir: List[str]) -> str:
    asm = [".text", ".global _start", "_start:"]
    for instruction in ir:
        parts = instruction.split()
        if parts[0] == 'ASSIGN':
            asm.append(f"  MOV {parts[1]}, {parts[2]}")
        elif parts[0] == 'PARAM':
            asm.append(f"  PUSH {parts[1]}")
        elif parts[0] == 'CALL':
            asm.append(f"  CALL {parts[1]}")
            if parts[2] != '0': asm.append(f"  ADD SP, {int(parts[2])*4}")
        elif parts[0] == 'MATH_CONST_FOLD':
            asm.append(f"  MOV {parts[2]}, {parts[1]}")
        elif parts[0] == '+':
            asm.append(f"  MOV {parts[3]}, {parts[1]}")
            asm.append(f"  ADD {parts[3]}, {parts[2]}")
    asm.append("  EXIT")
    return "\n".join(asm)

# ==========================================
# ENTRY POINT
# ==========================================
def compile_code(source_code: str):
    try:
        tokens = Lexer.tokenize(source_code)
        ast = Parser(tokens).parse()
        SemanticAnalyzer().analyze(ast)
        ir = generate_ir(ast)
        opt_ir = optimize_ir(ir)
        asm = generate_assembly(opt_ir)
        
        os.makedirs("assembly_files", exist_ok=True)
        filepath = os.path.join("assembly_files", "output_assembly.txt")
        with open(filepath, 'w') as out_f:
            out_f.write(asm)
            
        print(f"Compilation successful! Target assembly automatically saved to '{filepath}'.")
    except Exception as e:
        print(str(e))
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python veritas_compiler.py <file.c>")
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        compile_code(f.read())
