from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import RefType
from Ghidra_Analysis_Desc2 import *

def identify_risky_function_references():
    function_names = list(VULNERABLE_FUNCTIONS.keys())
    
    for function_name in function_names:
        description = VULNERABLE_FUNCTIONS[function_name] 
        
        function = locate_function(function_name)
        if function is not None:
            function_address = function.getEntryPoint() 
            references = getReferencesTo(function_address)
            
            if references: #if there are any references
                print("\n%s %s (Function Address: %s)" % (function_name, description, function_address))


def locate_function(name):
    func_mgr = currentProgram.getFunctionManager()
    func_itr = func_mgr.getFunctions(True) 
    
    while func_itr.hasNext():
        func = func_itr.next()
        if func.getName() == name: 
            return func
    return None


print("Below are the possible vulnerable functions, vulnerabilities details, and memory address \n")
print("**********************************************")

identify_risky_function_references()

print("**********************************************")
