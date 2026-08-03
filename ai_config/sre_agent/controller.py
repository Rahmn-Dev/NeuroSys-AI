from typing import Annotated, Any, Dict, List, Sequence, TypedDict
import operator
import json
import re

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

class TaskState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    goal: str
    plan: dict  # {"investigation_id": "...", "title": "...", "tasks": [...]}
    findings: dict # {"investigation_id": "...", "title": "...", "findings": [...]}
    iteration: int
    is_completed: bool

class AutonomousController:
    def __init__(self, llm, tools, system_prompt: str = ""):
        self.llm = llm
        self.tools = tools
        self.tool_node = ToolNode(tools)
        self.system_prompt = system_prompt

    def build_graph(self):
        workflow = StateGraph(TaskState)
        
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("agent", self.agent_node)
        workflow.add_node("tools", self.tool_node)
        workflow.add_node("reflector", self.reflector_node)
        
        workflow.set_entry_point("planner")
        
        workflow.add_edge("planner", "agent")
        
        def should_continue(state: TaskState):
            messages = state.get("messages", [])
            last_message = messages[-1]
            if getattr(last_message, "tool_calls", None):
                return "tools"
            if state.get("is_completed", False):
                return END
            return END
            
        workflow.add_conditional_edges(
            "agent",
            should_continue,
            {
                "tools": "tools",
                END: END
            }
        )
        
        workflow.add_edge("tools", "reflector")
        
        def check_reflection(state: TaskState):
            if state.get("iteration", 0) > 15:
                return END
            if state.get("is_completed", False):
                return END
            return "planner" # Always check plan after reflection
            
        workflow.add_conditional_edges(
            "reflector",
            check_reflection,
            {
                "planner": "planner",
                END: END
            }
        )
        
        return workflow.compile()

    def planner_node(self, state: TaskState):
        goal = state["goal"]
        existing_plan = state.get("plan", {})
        
        if not existing_plan or not existing_plan.get("tasks"):
            prompt = f"""You are an AI system agent planning an investigation for this goal: {goal}
CRITICAL PLANNER SAFETY GUARDS:
1. Tasks must describe actions performed by the AI agent itself.
2. Never generate steps intended for a human user to do.
3. If the goal is a casual conversation or identity question (e.g. "analyze meaning of hello", "search personal files to know user identity"), DO NOT generate tasks for it. Just output ["Respond to user"].
4. Focus on executable reasoning and tool actions (e.g. 'Collect CPU stats', 'Inspect nginx error logs').
Respond ONLY with a JSON array of strings representing the step-by-step tasks.
Example: ["Check workspace", "Find logs", "Analyze data"]"""
            
            response = self.llm.with_config({"tags": ["planner_llm"]}).invoke([HumanMessage(content=prompt)])
            try:
                json_str = re.search(r'\[.*\]', response.content, re.DOTALL).group(0)
                tasks = json.loads(json_str)
                existing_plan["tasks"] = [{"task": t, "status": "pending"} for t in tasks]
            except:
                existing_plan["tasks"] = [{"task": "Investigate and solve the issue", "status": "pending"}]
            return {"plan": existing_plan, "iteration": state.get("iteration", 0)}
        else:
            # We can optionally dynamically update the plan here based on findings
            # For simplicity, we just keep the existing plan.
            pass
            
        return {"plan": existing_plan}

    def agent_node(self, state: TaskState):
        goal = state["goal"]
        plan = state.get("plan", {})
        findings = state.get("findings", {})
        
        tasks_list = plan.get("tasks", [])
        findings_list = findings.get("findings", [])
        
        plan_text = "\n".join([f"- [{'x' if p['status']=='completed' else ' '}] {p['task']}" for p in tasks_list])
        findings_text = "\n".join([f"- {f}" for f in findings_list]) if findings_list else "None yet."
        
        sys_msg = SystemMessage(content=f"""{self.system_prompt}

## Task State
Goal: {goal}

Current Plan:
{plan_text}

Findings so far:
{findings_text}

Determine the next tool to run based on the plan.
If the goal is completely achieved and all necessary steps are done, output your final answer directly to the user.
DO NOT repeat the task plan in your thought process or output. Just execute the next tool silently or provide the final answer.
""")
        
        messages = [sys_msg] + state["messages"]
        response = self.llm.bind_tools(self.tools).with_config({"tags": ["agent_llm"]}).invoke(messages)
        
        is_completed = False
        if not getattr(response, "tool_calls", None):
            is_completed = True
            
        return {"messages": [response], "is_completed": is_completed}

    def reflector_node(self, state: TaskState):
        messages = state["messages"]
        
        # Extract latest tool messages
        tool_messages = []
        for i in range(len(messages)-1, -1, -1):
            if isinstance(messages[i], AIMessage):
                break
            if isinstance(messages[i], ToolMessage):
                tool_messages.append(messages[i])
                
        tool_messages.reverse()
        
        if not tool_messages:
            return {"iteration": state.get("iteration", 0) + 1}
            
        outputs = "\n".join([f"Tool {m.name} output: {m.content}" for m in tool_messages])
        
        prompt = f"""Tool Execution Results:
{outputs}

Current Plan:
{json.dumps(state.get("plan", []))}

Analyze the tool outputs. 
1. List any NEW findings (bullet points).
2. Which tasks in the plan are now completed?

Respond strictly in JSON:
{{
  "new_findings": ["finding 1", "finding 2"],
  "completed_tasks": ["Exact task name string from plan"]
}}
"""
        response = self.llm.with_config({"tags": ["reflector_llm"]}).invoke([HumanMessage(content=prompt)])
        plan = state.get("plan", {})
        findings = state.get("findings", {})
        
        try:
            json_str = re.search(r'\{.*\}', response.content, re.DOTALL).group(0)
            data = json.loads(json_str)
            new_findings = data.get("new_findings", [])
            completed_tasks = data.get("completed_tasks", [])
            
            for p in plan.get("tasks", []):
                if p["task"] in completed_tasks:
                    p["status"] = "completed"
                    
            if "findings" not in findings:
                findings["findings"] = []
            findings["findings"].extend(new_findings)
        except Exception:
            pass
            
        return {"findings": findings, "plan": plan, "iteration": state.get("iteration", 0) + 1}
