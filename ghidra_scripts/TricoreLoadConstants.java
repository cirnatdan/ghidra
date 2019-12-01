//TODO write a description for this script
//@author
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.math.BigInteger;

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

        public TricoreConstantPropagationEvaluator() {
            super(true);
            constantPropagationAnalyzer = new ConstantPropagationAnalyzer(currentProgram.getLanguage().getProcessor().toString());
        }

        @Override
        public boolean evaluateContext(VarnodeContext context, Instruction instr) {

            if (instr.getNumOperands() == 2) {
                Register dstReg = instr.getRegister(0);
                Register srcReg = null;
                Scalar scalar = null;

                Object[] srcRegAndScalar = instr.getOpObjects(1);

                if (dstReg == null) {
                    return false;
                }

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

                if (askRegisterValue(srcReg.getName()) && context.getValue(srcReg, false) == null) {
                    String valForRegister;
                    try {
                        valForRegister = askString("Set value for " + srcReg.getName(), "Value for " + srcReg.getName() + ":");
                        BigInteger val = new BigInteger(valForRegister, 16);
                        context.setValue(srcReg, val);
                        System.out.println("Reg " + srcReg.getName() + " set value to: " + context.getValue(srcReg, false));
                    } catch (CancelledException e) {
                        e.printStackTrace();
                    }

                }

                if (isStaticRegisterValue(srcReg.getName())) {
                    Long srcVal = Long.valueOf(context.getValue(srcReg, false).longValue() + scalar.getValue());
                    Address refAddr = instr.getMinAddress().getNewAddress(srcVal);
                    markAsConst(refAddr, Undefined4DataType.dataType);
                }

                if (context.getValue(dstReg, false) == null && context.getValue(srcReg, false) != null) {
                    Long newDstValue = Long.valueOf(context.getValue(srcReg, false).longValue() + scalar.getValue());
                    context.setValue(dstReg, BigInteger.valueOf(newDstValue));
                    System.out.println("Reg " + dstReg.getName() + " set value to: " + context.getValue(srcReg, false));

                    Address refAddr = instr.getMinAddress().getNewAddress(newDstValue);
                    instr.addOperandReference(0, refAddr, RefType.DATA, SourceType.ANALYSIS);

                    markAsConst(refAddr, getDataType(instr));

                } else if (isAddressRegister(dstReg) && context.getValue(dstReg, false) != null) {
                    Long newDstValue = context.getValue(dstReg, false).longValue();
                    Address refAddr = instr.getMinAddress().getNewAddress(newDstValue);

                    if (refAddr != null && refAddr.toString().startsWith("8")) {
                        System.out.println("Marking const for " + dstReg.getName() + " " + refAddr.toString());
                        markAsConst(refAddr, getDataType(instr));
                    }
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
                data = currentProgram.getListing().getDefinedDataAt(refAddr);
            } catch (DataTypeConflictException e) {
                e.printStackTrace();
                // ignore data type conflict
            }

            if (data != null && data.getDataType().getSettingsDefinitions() != null) {
                constantPropagationAnalyzer.markDataAsConstant(data);
            }
        }

        private DataType getDataType(Instruction instr) {
            System.out.println(instr);

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
