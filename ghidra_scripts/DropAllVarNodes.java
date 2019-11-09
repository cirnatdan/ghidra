//TODO write a description for this script
//@author
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;

public class DropAllVarNodes extends GhidraScript {

    @Override
    public void run() throws Exception {

        long numInstructions = currentProgram.getListing().getNumInstructions();
        monitor.initialize((int) (numInstructions));
        monitor.setMessage("Constant Propogation Markup");

        // set up the address set to restrict processing
        AddressSet restrictedSet = new AddressSet(currentSelection);
        if (restrictedSet.isEmpty()) {
            Function curFunc = currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
            if (curFunc != null) {
                restrictedSet = new AddressSet(curFunc.getEntryPoint());
            } else {
                restrictedSet = new AddressSet(currentLocation.getAddress());
            }

        }

        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);

        // iterate over all functions within the restricted set
        FunctionIterator fiter = currentProgram.getFunctionManager().getFunctions(restrictedSet, true);
        while (fiter.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }

            // get the function body
            Function func = fiter.next();
            Address start = func.getEntryPoint();

            // decompile func
            DecompileResults decompileResults = decompInterface.decompileFunction(func, 5, getMonitor());
            System.out.println("Decompiled completed: " + decompileResults.decompileCompleted());

            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
            HighFunction highFunction = decompileResults.getHighFunction();

            Iterator<PcodeOpAST> itPCodeOpAst = highFunction.getPcodeOps();
            while (itPCodeOpAst.hasNext()) {
                PcodeOpAST pcodeOp = itPCodeOpAst.next();

                if (pcodeOp.getOpcode() != PcodeOp.LOAD) {
                    continue;
                }

                println(pcodeOp.toString());

                // set all varnodes to null
                for (int i = 0; i < pcodeOp.getInputs().length; i++) {
                    pcodeOp.setInput(null, i);
                    if (pcodeOp.getInput(i) != null) {
                        throw new RuntimeException("varnode is not null");
                    }
                }

                // set output to null
                pcodeOp.setOutput(null);
            }

            String oldC = decompiledFunction.getC();
            DecompileResults dr = decompInterface.decompileFunction(highFunction.getFunction(), 5, getMonitor());
            String newC = dr.getDecompiledFunction().getC();

            println("C-code is equal: " + oldC.equals(newC));
        }
    }

}
