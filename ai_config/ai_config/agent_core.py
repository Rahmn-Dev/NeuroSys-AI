import os
import asyncio
import time
import uuid
from django.conf import settings
from chatbot.models import ChatMessage, ChatSession
from asgiref.sync import sync_to_async

from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

GEMINI_API_KEY = getattr(settings, "GEMINI_KEY", os.environ.get("GEMINI_API_KEY", ""))
os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY

@tool
def execute_shell(command: str) -> str:
    """Executes a bash command and returns the output."""
    import subprocess
    try:
        res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        return res.stdout + "\n" + res.stderr
    except Exception as e:
        return str(e)

@tool
def read_file(path: str) -> str:
    """Reads the content of a file."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

@tool
def write_file(path: str, content: str) -> str:
    """Writes content to a file."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        return "Success"
    except Exception as e:
        return f"Error writing file: {str(e)}"

tools = [execute_shell, read_file, write_file]

class AntigravitySysAdmin:
    def __init__(self, session_id):
        self.session_id = session_id
        
        import subprocess
        try:
            pwd = subprocess.run("pwd", shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
            whoami = subprocess.run("whoami", shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        except:
            pwd = "/home/user"
            whoami = "user"
            
        self.system_prompt = (
            "You are Enterprise Linux Auto-SysAdmin, an advanced autonomous AI agent.\n"
            "You operate inside a sophisticated web IDE with Multi-Terminal and Artifacts features.\n"
            f"Context: Your current working directory is {pwd} and you are running as {whoami}.\n"
            "Your goal is to be a highly intelligent assistant that can plan, explore, analyze, and execute tasks.\n"
            "Use the provided tools to interact with the system.\n"
            "Be extremely articulate and professional. Do not offer conversational filler."
        )

    def _get_llm(self, provider: str):
        if provider == "mistral":
            from langchain_mistralai import ChatMistralAI
            api_key = getattr(settings, "MISTRAL_KEY", os.environ.get("MISTRAL_API_KEY", ""))
            return ChatMistralAI(model="mistral-large-latest", mistral_api_key=api_key)
        elif provider == "ollama":
            from langchain_ollama import ChatOllama
            return ChatOllama(model="llama3.1") # default ollama model
        else:
            # Default to Gemini
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=GEMINI_API_KEY)

    async def stream_workflow(self, user_message, provider="gemini"):
        @sync_to_async
        def get_valid_session():
            session_id_str = str(self.session_id)
            if session_id_str == "null" or session_id_str == "":
                new_session = ChatSession.objects.create()
                return new_session.id
            try:
                session_obj, _ = ChatSession.objects.get_or_create(id=uuid.UUID(session_id_str))
                return session_obj.id
            except ValueError:
                new_session = ChatSession.objects.create()
                return new_session.id
                
        @sync_to_async
        def fetch_history(session_id):
            return list(ChatMessage.objects.filter(session_id=session_id).order_by('created_at'))

        db_session_id = await get_valid_session()
        
        @sync_to_async
        def save_message(sender, msg, metadata=None):
            if metadata is None: metadata = {}
            ChatMessage.objects.create(session_id=db_session_id, sender=sender, message=msg, metadata=metadata)
            
        await save_message("user", user_message)
        
        history_msgs = await fetch_history(db_session_id)
        
        messages = [SystemMessage(content=self.system_prompt)]
        for msg in history_msgs[-20:-1]:
            if msg.sender.lower() == "user":
                messages.append(HumanMessage(content=msg.message))
            else:
                messages.append(AIMessage(content=msg.message))
        
        messages.append(HumanMessage(content=user_message))
        
        yield {"type": "session_id", "content": str(db_session_id)}
        
        try:
            llm = self._get_llm(provider)
            agent_executor = create_react_agent(llm, tools)
            
            events_history = []
            final_ai_message = ""
            
            async for event in agent_executor.astream_events({"messages": messages}, version="v2"):
                kind = event["event"]
                name = event.get("name")
                
                if kind == "on_chat_model_stream":
                    chunk = event["data"]["chunk"]
                    if isinstance(chunk.content, str) and chunk.content:
                        final_ai_message += chunk.content
                        yield {"type": "message_chunk", "content": final_ai_message}
                
                elif kind == "on_tool_start":
                    tool_name = name
                    args = event["data"].get("input", {})
                    cmd = args.get("command", "") or args.get("path", "")
                    run_id = event.get("run_id", "")
                    evt = {
                        "type": "tool_start", 
                        "tool": tool_name, 
                        "title": f"Running {tool_name}", 
                        "command": str(cmd),
                        "step_id": run_id
                    }
                    events_history.append(evt)
                    yield evt
                
                elif kind == "on_tool_end":
                    res_str = str(event["data"].get("output", "No output"))
                    run_id = event.get("run_id", "")
                    evt = {
                        "type": "tool_end", 
                        "tool": name, 
                        "result": res_str,
                        "step_id": run_id
                    }
                    events_history.append(evt)
                    yield evt
        except Exception as e:
            yield {"type": "error", "content": f"AI Engine Error ({provider}): {str(e)}"}
            
        if final_ai_message or events_history:
            await save_message("ai", final_ai_message, metadata={"events": events_history})
            
        yield {"type": "complete", "content": {"summary": "Workflow completed", "start_time": time.time(), "end_time": time.time(), "duration": 0}}
