"""
Universal Execution Layer for Autonomous SRE Agent.

This abstracts the concrete execution mechanism (e.g., Python function calls, 
PTY interactive shell) away from the Worker reasoning loop. The Worker simply 
requests capabilities and actions, and the Executor handles the backend execution, 
observation, and interruption.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from .tools.registry import ToolRegistry


class ExecutorInterface(ABC):
    """Abstract interface for all execution backends."""
    
    @abstractmethod
    def execute(self, capability: str, action: str, target: str, kwargs: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Execute an action based on capability.
        Returns: (success: bool, output: str)
        """
        pass
        
    @abstractmethod
    def observe(self) -> str:
        """Observe the current state or output stream."""
        pass
        
    @abstractmethod
    def interrupt(self) -> bool:
        """Interrupt a running execution."""
        pass
        
    @abstractmethod
    def stream_output(self):
        """Stream output from the execution."""
        pass


class PythonToolExecutor(ExecutorInterface):
    """
    Initial implementation mapping capability requests to the existing 
    Python-based Tool Registry.
    """
    
    def __init__(self, tool_map: Dict[str, Any]):
        self.registry = ToolRegistry()
        self.tool_map = tool_map
        self.last_output = ""
        
    def _resolve_tool(self, capability: str, action: str, target: str) -> Optional[str]:
        """
        Heuristic mapping from capability/action to an actual registered tool.
        """
        # Specific capability mappings
        if capability == "service_management":
            return "service_manager"
        elif capability == "process_management":
            return "process_manager"
        elif capability == "package_management":
            return "package_manager"
        elif capability == "network_operation":
            # For now, fallback to diagnostic execute if specific tool not found
            return "terminal_execute" 
        elif capability in ["runtime_execution", "command_execution"]:
            return "terminal_execute"
        elif capability in ["workspace_operation", "filesystem_operation"]:
            if action in ["read_file", "read"]:
                return "read_file"
            elif action in ["write_file", "write", "create_file"]:
                return "write_file"
            elif action in ["patch_file", "edit_file", "modify_file"]:
                return "edit_file"
            elif action in ["search_code", "search_files"]:
                return "search_files"
            elif action in ["inspect_project", "inspect_environment", "list_directory"]:
                return "list_directory"
            elif action in ["run_command", "build_project"]:
                return "terminal_execute"
        elif capability == "environment_discovery":
            if action in ["system_info", "inspect_runtime"]:
                return "system_info"
            elif action in ["inspect_project", "list_directory"]:
                return "list_directory"
            elif action == "read_file":
                return "read_file"
            # Default discovery command
            return "terminal_execute"
            
        # Fallback search through registry capabilities
        for name, entry in self.registry._entries.items():
            if capability in entry.meta.capabilities:
                return name
                
        return None
        
    def _map_args(self, tool_name: str, action: str, target: str, kwargs: dict) -> dict:
        """Map generic action/target to the specific schema of the python tool."""
        args = {}
        if tool_name == "service_manager":
            # action mapping
            if "restart" in action: args["action"] = "restart"
            elif "start" in action: args["action"] = "start"
            elif "stop" in action: args["action"] = "stop"
            elif "status" in action: args["action"] = "status"
            else: args["action"] = action
            args["service_name"] = target
            
        elif tool_name == "process_manager":
            if "kill" in action: args["action"] = "kill"
            elif "search" in action: args["action"] = "search"
            else: args["action"] = "list"
            args["target"] = target
            
        elif tool_name == "package_manager":
            args["action"] = action
            args["package"] = target
            
        elif tool_name == "terminal_execute":
            # For direct execution, the action/target usually implies a shell command.
            if kwargs and "command" in kwargs:
                args["command"] = kwargs["command"]
            else:
                args["command"] = f"{action} {target}".strip() if target else action
                
        elif tool_name == "log_reader":
            args["source"] = target
            args["lines"] = kwargs.get("lines", 50) if kwargs else 50
            args["filter_pattern"] = kwargs.get("filter", "") if kwargs else ""
            
        elif tool_name in ["read_file", "list_directory", "file_info"]:
            args["path"] = target or kwargs.get("path", ".")
            
        elif tool_name == "write_file":
            args["path"] = target or kwargs.get("path", "")
            args["content"] = kwargs.get("content", "")
            
        elif tool_name == "edit_file":
            args["path"] = target or kwargs.get("path", "")
            args["old_text"] = kwargs.get("old_text", "")
            args["new_text"] = kwargs.get("new_text", "")
            
        elif tool_name == "search_files":
            args["pattern"] = target or kwargs.get("pattern", "")
            args["path"] = kwargs.get("path", ".")
            if "file_glob" in kwargs:
                args["file_glob"] = kwargs["file_glob"]
            
        else:
            # Pass through any provided kwargs
            if kwargs:
                args.update(kwargs)
                
        return args

    def execute(self, capability: str, action: str, target: str, kwargs: Dict[str, Any] = None) -> Tuple[bool, str]:
        tool_name = self._resolve_tool(capability, action, target)
        
        if not tool_name or tool_name not in self.tool_map:
            self.last_output = f"Executor Error: Could not resolve capability '{capability}' and action '{action}' to an available tool."
            return False, self.last_output
            
        tool = self.tool_map[tool_name]
        mapped_args = self._map_args(tool_name, action, target, kwargs)
        
        try:
            # Langchain BaseTool .invoke()
            result = tool.invoke(mapped_args)
            self.last_output = str(result)
            # Basic heuristical success check: if there's "Error" or it returned empty for a mutation
            if "error" in self.last_output.lower() and "status" not in action:
                return False, self.last_output
            return True, self.last_output
        except Exception as e:
            self.last_output = f"Execution failed: {str(e)}"
            return False, self.last_output
            
    def observe(self) -> str:
        return self.last_output
        
    def interrupt(self) -> bool:
        # Python tools are synchronous via LangChain in this context, so interrupt is a no-op 
        # until we get to PTYExecutor.
        return False
        
    def stream_output(self):
        pass
