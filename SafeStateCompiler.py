class SafeStateCompiler:
    def __init__(self, code):
        self.code = code
        self.tokens = []
        self.ast = []
        self.ir = []
        self.vulnerabilities = []

    #Lexical Analysis
    def lexer(self):
        line_num = 1
        i = 0
        n = len(self.code)
        
        while i < n:
            c = self.code[i]
            if c == '\n':
                line_num += 1
                i += 1
            elif c.isspace():
                i += 1
            elif c.isalpha() or c == '_':
                start = i
                while i < n and (self.code[i].isalnum() or self.code[i] == '_'):
                    i += 1
                self.tokens.append(('ID', self.code[start:i], line_num))
            elif c.isdigit():
                start = i
                while i < n and self.code[i].isdigit():
                    i += 1
                self.tokens.append(('NUMBER', self.code[start:i], line_num))
            elif c == '"':
                start = i
                i += 1
                while i < n and self.code[i] != '"':
                    i += 1
                i += 1 
                self.tokens.append(('STRING', self.code[start:i], line_num))
            else:
                self.tokens.append(('SYMBOL', c, line_num))
                i += 1
                
        return self.tokens

    #Syntax Analysis
    def parser(self):

        stmt = []
        for t in self.tokens:
            stmt.append(t)
            if t[1] in [';', '{', '}']:
                self.ast.append(stmt)
                stmt = []
        if stmt:
            self.ast.append(stmt)
        return self.ast

    #Semantic & Security Analysis
    def semantic_analyzer(self):
        freed_pointers = set()
        
        for stmt in self.ast:
            if not stmt: continue
            line = stmt[0][2]
            vals = [t[1] for t in stmt]
            types = [t[0] for t in stmt]
            
            #Failure to Scrub/Clear Memory 
            if 'memset' in vals:
                self.vulnerabilities.append({
                    "issue": "Failure to Scrub/Clear Memory",
                    "line": line,
                    "severity": "Medium",
                    "details": "memset() optimization risk detected. Compiler may silently remove this during optimization.",
                    "fix": "Use explicit_bzero() or memset_s() to ensure memory is cleared."
                })
            
            #Stack-based Vulnerabilities & Buffer Overflows
            if 'gets' in vals:
                self.vulnerabilities.append({
                    "issue": "Buffer Overflow Risk",
                    "line": line,
                    "severity": "Critical",
                    "details": "gets() does not check buffer length, allowing attackers to overwrite memory.",
                    "fix": "Use fgets() instead, which enforces a maximum read size."
                })
            elif 'strcpy' in vals:
                self.vulnerabilities.append({
                    "issue": "Unbounded Memory Copy",
                    "line": line,
                    "severity": "High",
                    "details": "strcpy() can overflow the destination buffer if the source string is too large.",
                    "fix": "Use strncpy() and manually ensure null-termination."
                })
            
            #Uncontrolled Format Strings
            if 'printf' in vals:
                idx = vals.index('printf')
                if len(vals) > idx + 2 and types[idx + 2] == 'ID': 
                    self.vulnerabilities.append({
                        "issue": "Format String Injection",
                        "line": line,
                        "severity": "Critical",
                        "details": "Unsanitized input is being passed directly to printf, allowing memory reading/writing.",
                        "fix": "Use printf(\"%s\", variable) instead."
                    })
            
            #Integer Overflow
            if '2147483647' in vals and '+' in vals:
                self.vulnerabilities.append({
                    "issue": "Integer Overflow/Underflow",
                    "line": line,
                    "severity": "High",
                    "details": "Arithmetic operation exceeds the 32-bit integer limit.",
                    "fix": "Implement strict bounds checking before performing the addition."
                })
                
            #Undefined Behavior (Use-After-Free)
            if 'free' in vals:
                idx = vals.index('free')
                if len(vals) > idx + 2:
                    freed_pointers.add(vals[idx + 2])
            else:
                for v in vals:
                    if v in freed_pointers:
                        self.vulnerabilities.append({
                            "issue": "Undefined Behavior (Use After Free)",
                            "line": line,
                            "severity": "Critical",
                            "details": f"Pointer '{v}' is accessed after being freed, which can lead to code execution.",
                            "fix": "Set the pointer to NULL immediately after calling free()."
                        })

    #Intermediate Representation Generation
    def generate_ir(self):
        for stmt in self.ast:
            self.ir.append("IR: " + " ".join([t[1] for t in stmt]))

    #Code Optimization
    def optimize(self):
        self.ir = [instr + " -> [Optimized]" for instr in self.ir]

    #Target Code Generation
    def generate_code(self):
        return ["ASM: " + instr for instr in self.ir]

    # Compilation Pipeline
    def compile(self):
        self.lexer()
        self.parser()
        self.semantic_analyzer()
        
        # If vulnerabilities exist, halt generation and return the report
        if self.vulnerabilities:
            return {
                "status": "HALTED",
                "message": f"Compilation blocked by Veritas Engine. {len(self.vulnerabilities)} vulnerabilities found.",
                "vulnerabilities": self.vulnerabilities
            }
            
        # Otherwise, proceed to IR and ASM generation
        self.generate_ir()
        self.optimize()
        compiled_code = self.generate_code()
        
        return {
            "status": "SUCCESS",
            "message": "Compilation Successful! AST is clean.",
            "vulnerabilities": [],
            "compiled_code": compiled_code
        }