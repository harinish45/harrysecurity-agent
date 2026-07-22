from nexus.tools.registry import tool_registry

def run(target: str, **kwargs) -> dict:
    return {"tool":"active_directory.kerberoast","domain":"active_directory","target":target,"status":"stub","findings":[]}

tool_registry.register("active_directory.kerberoast", run)
