//TODO write a description for this script
//@author
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileReader;
import java.io.LineNumberReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class TricoreLoadConstants extends GhidraScript {

    private class TricoreConstantPropagationEvaluator extends ConstantPropagationContextEvaluator {

        ConstantPropagationAnalyzer constantPropagationAnalyzer;
        File a2l;

        public TricoreConstantPropagationEvaluator() {
            super(true);
            constantPropagationAnalyzer = new ConstantPropagationAnalyzer(currentProgram.getLanguage().getProcessor().toString());

            try {
                a2l = askFile("Provide optional a2l file", "OK");
            } catch (CancelledException e) {
                e.printStackTrace();
            }
        }

        @Override
        public boolean evaluateContext(VarnodeContext context, Instruction instr) {
            Register dstReg = null;
            Register srcReg = null;
            Scalar scalar = null;

            // check if any load instr
            if (instr.getNumOperands() == 2 && instr.getRegister(0) != null) {
                dstReg = instr.getRegister(0);

                if (dstReg.getName().startsWith("a") == false) {
                    return false;
                }

                Object[] srcRegAndScalar = instr.getOpObjects(1);

                if (srcRegAndScalar.length == 2) {
                    if (srcRegAndScalar[0] instanceof Register) {
                        srcReg = (Register) srcRegAndScalar[0];
                    }

                    if (srcRegAndScalar[1] instanceof Scalar) {
                        scalar = (Scalar) srcRegAndScalar[1];
                    }
                }

                if (srcReg == null || scalar == null) {
                    return false;
                }

            } else {
                return false;
            }

            if (instr.getAddress().toString().equals("8012c22c")) {
                System.out.println("Found 8012c22c val " + context.getValue(dstReg, false));
            }

            // check for special register
            if (askRegisterValue(srcReg.getName()) && context.getValue(srcReg, false) == null) { // val is not set yet
                String valForRegister;
                try {
                    valForRegister = askString("Set value for " + srcReg.getName(), "Value for " + srcReg.getName() + ":"); // ask the val
                    BigInteger val = new BigInteger(valForRegister, 16);
                    context.setValue(srcReg, val);
                    System.out.println("Reg " + srcReg.getName() + " set value to: " + context.getValue(srcReg, false));
                } catch (CancelledException e) {
                    e.printStackTrace();
                }
            } else if (askRegisterValue(srcReg.getName()) && context.getValue(srcReg, false) != null) {
                Long srcVal = Long.valueOf(context.getValue(srcReg, false).longValue());
                Address refAddr = instr.getMinAddress().getNewAddress(srcVal);
                instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);
                markAsConst(refAddr, Undefined4DataType.dataType); // propagate the src address, e.g. a9 = 8016D340
            }

            if (context.getValue(srcReg, false) != null) {
                Long srcVal = Long.valueOf(context.getValue(srcReg, false).longValue() + scalar.getValue());
                Address refAddr = instr.getMinAddress().getNewAddress(srcVal);
                instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);

                if (isStaticRegisterValue(srcReg.getName())) {
                    markAsConst(refAddr, Undefined4DataType.dataType); // propagate the src address, e.g. a9 = 8016D340[0xabc]
                }
            }

            if (context.getValue(dstReg, false) == null && context.getValue(srcReg, false) != null) { // propagate dst, e.g. aX = aY[0xabc]
                Long newDstValue = Long.valueOf(context.getValue(srcReg, false).longValue() + scalar.getValue());
                context.setValue(dstReg, BigInteger.valueOf(newDstValue));
                System.out.println("Reg " + dstReg.getName() + " set value to: " + context.getValue(srcReg, false));

                Address refAddr = instr.getMinAddress().getNewAddress(newDstValue);
                instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);

                markAsConst(refAddr, getDataType(instr));
            }

            if (isAddressRegister(dstReg) && context.getValue(dstReg, false) != null) {
                Long newDstValue = context.getValue(dstReg, false).longValue();
                Address refAddr = instr.getMinAddress().getNewAddress(newDstValue);

                if (refAddr != null && refAddr.toString().startsWith("8")) {
                    System.out.println("Marking const for " + dstReg.getName() + " " + refAddr.toString());
                    instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);
                    markAsConst(refAddr, getDataType(instr));
                }
            }

            return false;
        }

        @Override
        public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address, int size, RefType refType) {
            return true; // just go ahead and mark up the instruction
        }

        private boolean askRegisterValue(String name) {
            switch (name) {
            case "a0":
            case "a1":
            case "a9":
                return true;
            default:
                return false;
            }
        }

        private boolean isStaticRegisterValue(String name) {
            switch (name) {
            case "a1":
            case "a9":
                return true;
            default:
                return false;
            }
        }

        private boolean isAddressRegister(Register reg) {
            return reg.toString().startsWith("a");
        }

        private void markAsConst(Address refAddr, DataType dataType) {
            Data data = null;
            try {
                data = currentProgram.getListing().createData(refAddr, dataType);

            } catch (CodeUnitInsertionException e) {
                data = currentProgram.getListing().getDefinedDataContaining(refAddr);

            } catch (DataTypeConflictException e) {
                e.printStackTrace();
                // ignore data type conflict
            }

            if (data != null && data.getDataType().getSettingsDefinitions() != null) {
                constantPropagationAnalyzer.markDataAsConstant(data);
            }

            labelAddress(refAddr);
        }

        private void labelAddress(Address refAddr) {

            try {
                if (a2l == null) {
                    createLabel(refAddr, "const_" + refAddr, true);

                } else {
                    // find line number of 0xADDRESS
                    LineNumberReader reader = new LineNumberReader(new FileReader(a2l));
                    String line = reader.readLine();
                    long lineNumberOfLabel = 0;
                    while (line != null) {
                        if (line.trim().equals("0x" + (refAddr.toString().toUpperCase()))) { // found addr
                            lineNumberOfLabel = reader.getLineNumber() - 4; // a2l name is 4 lines above
                            break;
                        }

                        line = reader.readLine();
                    }
                    reader.close();

                    if (lineNumberOfLabel != 0) { // found the a2l name
                        try (Stream<String> lines = Files.lines(Paths.get(a2l.getPath()), StandardCharsets.ISO_8859_1)) { // utf8 will crash
                            String a2lLabel = lines.skip(lineNumberOfLabel).findFirst().get().trim(); // read line
                            System.out.println("Loaded a2l label '" + a2lLabel + "' on line " + lineNumberOfLabel);
                            createLabel(refAddr, a2lLabel, true); // set the name
                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        }

        private DataType getDataType(Instruction instr) {
            if (instr.getMnemonicString().equals("lea")) {
                return Undefined4DataType.dataType;

            } else if (instr.getMnemonicString().startsWith("ld.")) {
                switch (instr.getMnemonicString().split("\\.")[1]) {
                case "bu":
                    return Undefined1DataType.dataType;
                case "h":
                    return Undefined2DataType.dataType;
                case "w":
                case "a":
                    return Undefined4DataType.dataType;
                default:
                    throw new RuntimeException("unknown type " + instr.getMnemonicString());
                }

            } else {
                throw new RuntimeException("unknown type " + instr.getMnemonicString());
            }

        }
    }

    @Override
    public void run() throws Exception {
        MessageLog log = new MessageLog();
        var fact = currentProgram.getAddressFactory().getDefaultAddressSpace();

        MemoryBlockUtils.createUninitializedBlock(currentProgram, false, "A0000000", fact.getAddress(0xA000_0000), 0x0FFF_FFFF, "Memory for A",
                "SourceBlockA?", true, true, false, log);

        MemoryBlockUtils.createUninitializedBlock(currentProgram, false, "C0000000", fact.getAddress(0xC000_0000), 0x0FFF_FFFF, "Memory for C",
                "SourceBlockC?", true, true, false, log);

        MemoryBlockUtils.createUninitializedBlock(currentProgram, false, "D0000000", fact.getAddress(0xD000_0000), 0x0FFF_FFFF, "Memory for D",
                "SourceBlockD?", true, true, false, log);


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

            ConstantPropagationContextEvaluator eval = new TricoreConstantPropagationEvaluator();

            SymbolicPropogator symEval = new SymbolicPropogator(currentProgram);

            symEval.flowConstants(start, func.getBody(), eval, true, monitor);
        }
    }

}
