package pcodefiles;

import docking.framework.SplashScreen;
import ghidra.util.task.TaskMonitorAdapter;

public class StatusReportingTaskMonitor extends TaskMonitorAdapter {
    @Override
    public synchronized void setCancelEnabled(boolean enable) {
        // Not permitted
    }

    @Override
    public void setMessage(String message) {
        SplashScreen.updateSplashScreenStatus(message);
    }
}
