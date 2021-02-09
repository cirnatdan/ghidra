package pcodefiles;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.EclipseIntegrationService;
import ghidra.app.services.GhidraScriptService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.COMMON,
        shortDescription = "Script Manager",
        description = "Manages scripts and automatically compiles and creates actions in the tool for each script.",
        servicesRequired = { ConsoleService.class},
        servicesProvided = { GhidraScriptService.class }
)
//@formatter:on
public class ScriptMgrPlugin extends GhidraScriptMgrPlugin {
    /**
     * {@link GhidraScriptMgrPlugin} is the entry point for all {@link GhidraScript} capabilities.
     *
     * @param tool the tool this plugin is added to
     */
    public ScriptMgrPlugin(PluginTool tool) {
        super(tool);
    }
}
