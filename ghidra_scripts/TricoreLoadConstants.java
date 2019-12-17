//Propagates TriCore register values.
//@author Alexander Kostenev
//@category Memory Propagtion
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
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

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

    /**
     * Propagates TriCore register values.
     */
    private class TricoreConstantPropagationEvaluator extends ConstantPropagationContextEvaluator {

        ConstantPropagationAnalyzer constantPropagationAnalyzer; // helper to mark memory addresses as const
        File a2l; // optional a2l file for labels
        Set<Address> sAlreadyLoadedA2lAddresses = new TreeSet<>(); // cash to improve performance on a2l load

        public TricoreConstantPropagationEvaluator() {
            super(true);
            constantPropagationAnalyzer = new ConstantPropagationAnalyzer(currentProgram.getLanguage().getProcessor().toString());

            try {
                a2l = askFile("Provide optional a2l file", "OK"); // load an a2l file
            } catch (CancelledException e) {
                e.printStackTrace();
            }
        }

        @Override
        public boolean evaluateContext(VarnodeContext context, Instruction instr) {
            Register dstReg = null;
            Register srcReg = null;
            Scalar scalar = null;

            // check if any load instr dst = src[scalar]
            if (instr.getNumOperands() == 2 && instr.getRegister(0) != null) {
                dstReg = instr.getRegister(0);

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

            // check for special register, a0, a1, a9, if their value is not set yet
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
            }

            // propagte the register address values
            if (askRegisterValue(srcReg.getName()) && context.getValue(srcReg, false) != null) {
                Long srcVal = Long.valueOf(context.getValue(srcReg, false).longValue());
                Address refAddr = instr.getMinAddress().getNewAddress(srcVal);
                instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);
                markAsConst(refAddr, Undefined4DataType.dataType); // propagate the src address, e.g. a9 = 8016D340
            }

            // propagate the src address + scalar
            if (context.getValue(srcReg, false) != null) {
                Long srcVal = Long.valueOf(context.getValue(srcReg, false).longValue() + scalar.getValue());
                Address refAddr = instr.getMinAddress().getNewAddress(srcVal);
                instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);
                markAsConst(refAddr, Undefined4DataType.dataType); // propagate the src address, e.g. a9 = 8016D340[0xabc]
            }

            // set the dst registers
            if (context.getValue(dstReg, false) == null && context.getValue(srcReg, false) != null) { // propagate dst, e.g. aX = aY[0xabc]
                Long newDstValue = Long.valueOf(context.getValue(srcReg, false).longValue() + scalar.getValue());
                context.setValue(dstReg, BigInteger.valueOf(newDstValue));
                System.out.println("Reg " + dstReg.getName() + " set value to: " + context.getValue(srcReg, false));

                Address refAddr = instr.getMinAddress().getNewAddress(newDstValue);
                instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);

                markAsConst(refAddr, getDataType(instr));
            }

            // if lea, propagate also, e.g. lea a2 = a9[0xabc]
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

        /**
         * Checks whether the register should load a value.
         *
         * @param name
         * @return
         */
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

        /**
         * Returns true if the register name start with "a"
         *
         * @param reg
         * @return
         */
        private boolean isAddressRegister(Register reg) {
            return reg.toString().startsWith("a");
        }

        /**
         * Marks the addr as const and labels it
         *
         * @param refAddr
         * @param dataType
         */
        private void markAsConst(Address refAddr, DataType dataType) {
            if (refAddr.toString().startsWith("8") == false) {
                return; // mark only if the address points to the flash
            }

            Data data = null;
            try {
                // try to create a new data on the addr
                data = currentProgram.getListing().createData(refAddr, dataType);

            } catch (CodeUnitInsertionException e) {
                // their is already a datatype defined, use it
                data = currentProgram.getListing().getDefinedDataContaining(refAddr);

            } catch (DataTypeConflictException e) {
                e.printStackTrace(); // ignore data type conflict
            }

            if (data != null && data.getDataType().getSettingsDefinitions() != null) {
                constantPropagationAnalyzer.markDataAsConstant(data);
            }

            labelAddress(refAddr); // label the addr
        }

        /**
         * Finds the refAddr in the a2l file to label it in the decompiler
         *
         * @param refAddr
         */
        private void labelAddress(Address refAddr) {
            if (sAlreadyLoadedA2lAddresses.add(refAddr) == false) {
                return; // this address is already labeled
            }

            try {
                if (a2l == null) { // a2l file not provided
                    createLabel(refAddr, "const_" + refAddr, true); // label it const_ADDR

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

                    if (lineNumberOfLabel != 0) { // found the a2l name line number
                        try (Stream<String> lines = Files.lines(Paths.get(a2l.getPath()), StandardCharsets.ISO_8859_1)) { // utf8 will crash
                            String a2lLabel = lines.skip(lineNumberOfLabel).findFirst().get().trim(); // read the name
                            System.out.println("Loaded a2l label '" + a2lLabel + "' on line " + lineNumberOfLabel);
                            createLabel(refAddr, a2lLabel, true); // set the name as label
                        }

                    } else {
                        createLabel(refAddr, "const_" + refAddr, true); // label it const_ADDR
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        }

        /**
         * Returns a matching datatype based on the instruction.
         *
         * @param instr
         * @return
         */
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
        var fact = currentProgram.getAddressFactory().getDefaultAddressSpace(); // get the AddressFactory

        // build address spaces for 0xA, 0xC, 0xD
        MemoryBlockUtils.createUninitializedBlock(currentProgram, false, "A0000000", fact.getAddress(0xA000_0000), 0x0FFF_FFFF, "Memory for A",
                "SourceBlockA?", true, true, false, log);

        MemoryBlockUtils.createUninitializedBlock(currentProgram, false, "C0000000", fact.getAddress(0xC000_0000), 0x0FFF_FFFF, "Memory for C",
                "SourceBlockC?", true, true, false, log);

        MemoryBlockUtils.createUninitializedBlock(currentProgram, false, "D0000000", fact.getAddress(0xD000_0000), 0x0FFF_FFFF, "Memory for D",
                "SourceBlockD?", true, true, false, log);


        long numInstructions = currentProgram.getListing().getNumInstructions();
        monitor.initialize((int) (numInstructions));
        monitor.setMessage("TriCore Constant Propogation Markup");

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
