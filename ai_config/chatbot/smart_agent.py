import psutil
import os
import subprocess
import openai
import json
import time
from dotenv import load_dotenv
from django.conf import settings
import os
# Load environment variables
load_dotenv()

class MCPClient:
    def __init__(self):
        openai.api_key = settings.OPENAI_KEY
        
    def process_complex_task(self, user_input):
        system_prompt = """
        You are an advanced Linux system administrator that can handle complex multi-step tasks.
        Break down complex requests into sequential steps with validation.
        
        For complex tasks, return JSON with:
        - "workflow": array of steps
        - "description": overall task description
        - "validation_points": checks to perform between steps
        
        Examples:
        
        1. "backup data ini lalu cek apakah ada data yang hilang":
        {
            "workflow": [
                {"step": 1, "command": "rsync -av /source/path/ /backup/path/", "description": "Backup data"},
                {"step": 2, "command": "diff -r /source/path/ /backup/path/", "description": "Compare source and backup"},
                {"step": 3, "command": "find /backup/path -type f | wc -l", "description": "Count backup files"},
                {"step": 4, "command": "find /source/path -type f | wc -l", "description": "Count source files"}
            ],
            "validation_points": ["Check file count match", "Verify no diff output"],
            "description": "Backup data and verify integrity"
        }
        
        2. "duplicate file ini sebanyak 10 data lalu pindahkan ke folder ini":
        {
            "workflow": [
                {"step": 1, "command": "ls -la /source/file.txt", "description": "Check source file exists"},
                {"step": 2, "command": "mkdir -p /target/folder", "description": "Create target folder"},
                {"step": 3, "command": "for i in {1..10}; do cp /source/file.txt /target/folder/file_$i.txt; done", "description": "Duplicate file 10 times"},
                {"step": 4, "command": "ls -la /target/folder/ | grep file_", "description": "Verify duplicated files"}
            ],
            "validation_points": ["Source file exists", "Target folder created", "10 files created"],
            "description": "Duplicate file 10 times and move to target folder"
        }
        """
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_input}
                ],
                temperature=0.3
            )
            
            return response.choices[0].message.content
        except Exception as e:
            return f"Error processing request: {str(e)}"


class SafeCommandExecutor:
    def __init__(self):
        # Whitelist of allowed commands
        self.allowed_commands = [
            'ls', 'cat', 'grep', 'find', 'wc', 'head', 'tail', 
            'ps', 'top', 'free', 'df', 'du', 'uptime', 'whoami',
            'pwd', 'which', 'file', 'stat', 'chmod', 'chown',
            'mkdir', 'rmdir', 'cp', 'mv', 'rsync', 'diff',
            'tar', 'gzip', 'gunzip', 'zip', 'unzip'
        ]
    
    def execute(self, command_json):
        """Execute simple command from JSON format"""
        try:
            if isinstance(command_json, str):
                try:
                    command_data = json.loads(command_json)
                    command = command_data.get('command', '').strip()
                except json.JSONDecodeError:
                    # If not JSON, treat as plain command
                    command = command_json.strip()
            else:
                command = command_json.get('command', '').strip()
            
            return self.execute_bash_command(command)
            
        except Exception as e:
            return {"error": str(e)}
    
    def execute_bash_command(self, command):
        """Execute complex bash commands with safety checks"""
        
        # Blacklist dangerous commands
        dangerous_patterns = [
            'rm -rf /', 'dd if=', 'mkfs', 'fdisk', 'parted',
            'format', 'del /f', 'deltree', '> /dev/', 'chmod 777 /',
            'chown root /', 'sudo su', 'su -', 'passwd'
        ]
        
        if any(pattern in command.lower() for pattern in dangerous_patterns):
            return {"error": "Dangerous command detected and blocked"}
        
        # Check if base command is allowed (for simple commands)
        cmd_base = command.split()[0] if command.split() else ""
        
        # Allow complex commands with pipes, loops, etc.
        complex_indicators = ['|', '&&', '||', ';', 'for', 'while', 'if']
        is_complex = any(indicator in command for indicator in complex_indicators)
        
        if not is_complex and cmd_base not in self.allowed_commands:
            return {"error": f"Command '{cmd_base}' not in allowed list"}
        
        try:
            result = subprocess.run(
                ['bash', '-c', command],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.getcwd()  # Execute in current directory
            )
            
            return {
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode,
                "command": command
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout (30s)"}
        except Exception as e:
            return {"error": str(e)}


class SmartAgent:
    def __init__(self):
        self.mcp_client = MCPClient()
        self.executor = SafeCommandExecutor()
        self.conversation_history = []
        self.current_goal = None
        self.context_memory = {}
        
        # Set OpenAI API key
        openai.api_key = os.getenv('OPENAI_API_KEY')
    
    def process_smart_workflow(self, user_query):
        """Main method to process user query with smart workflow"""
        self.current_goal = user_query
        self.conversation_history = [
            {"role": "user", "content": user_query}
        ]
        
        workflow_result = {
            "steps": [],
            "final_status": "in_progress",
            "goal": user_query,
            "start_time": time.time()
        }
        
        print(f"🤖 Starting smart workflow for: {user_query}")
        
        # Start the conversation loop
        step_count = 0
        max_steps = 10  # Prevent infinite loops
        
        while step_count < max_steps:
            print(f"\n--- Step {step_count + 1} ---")
            
            # Ask AI what to do next
            next_action = self.get_next_action()
            print(f"AI Decision: {next_action}")
            
            if next_action.get("action") == "complete":
                workflow_result["final_status"] = "completed"
                workflow_result["summary"] = next_action.get("summary")
                print("✅ Workflow completed!")
                break
                
            elif next_action.get("action") == "execute":
                # Execute the command
                command = next_action.get("command")
                reasoning = next_action.get("reasoning")
                
                print(f"Reasoning: {reasoning}")
                print(f"Executing: {command}")
                
                execution_result = self.execute_with_context(command)
                
                # Add to workflow results
                workflow_result["steps"].append({
                    "step": step_count + 1,
                    "reasoning": reasoning,
                    "command": command,
                    "result": execution_result,
                    "timestamp": time.time()
                })
                
                # Feed result back to AI
                self.add_execution_result_to_conversation(command, execution_result)
                
                print(f"Result: {execution_result.get('output', 'No output')[:100]}...")
                
                step_count += 1
                
            else:
                workflow_result["final_status"] = "failed"
                workflow_result["error"] = next_action.get("error", "Unknown error")
                print(f"❌ Workflow failed: {workflow_result['error']}")
                break
        
        workflow_result["end_time"] = time.time()
        workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
        
        return workflow_result
    
    def get_next_action(self):
        """Ask AI what to do next based on conversation history"""
        system_prompt = f"""
        You are a smart Linux system administrator AI agent. 
        Your goal: {self.current_goal}
        
        Based on the conversation history, decide the next action:
        
        1. If goal is achieved → return {{"action": "complete", "summary": "description"}}
        2. If need to execute command → return {{"action": "execute", "command": "command", "reasoning": "why"}}
        3. If failed → return {{"action": "fail", "error": "reason"}}
        
        Be smart and adaptive:
        - Check command results before proceeding
        - Adjust strategy based on previous outputs
        - Validate each step before moving to next
        - Handle errors gracefully
        - Use absolute paths when possible
        - Be specific with file and directory names
        
        Context memory: {json.dumps(self.context_memory)}
        
        IMPORTANT: Return only valid JSON format. No additional text.
        """
        
        messages = [
            {"role": "system", "content": system_prompt}
        ] + self.conversation_history
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",  # Use GPT-3.5 for cost efficiency
                messages=messages,
                temperature=0.1,
                max_tokens=200
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Try to extract JSON if response has extra text
            if not ai_response.startswith('{'):
                # Look for JSON in the response
                start = ai_response.find('{')
                end = ai_response.rfind('}') + 1
                if start >= 0 and end > start:
                    ai_response = ai_response[start:end]
            
            return json.loads(ai_response)
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"AI Response: {ai_response}")
            return {"action": "fail", "error": f"Invalid JSON response: {str(e)}"}
        except Exception as e:
            return {"action": "fail", "error": str(e)}
    
    def execute_with_context(self, command):
        """Execute command with current context"""
        return self.executor.execute_bash_command(command)
    
    def add_execution_result_to_conversation(self, command, result):
        """Add command execution result to conversation history"""
        
        # Update context memory with important info
        self.update_context_memory(command, result)
        
        # Add to conversation
        self.conversation_history.append({
            "role": "assistant", 
            "content": f"Executed: {command}"
        })
        
        # Limit output length to prevent token overflow
        output = result.get('output', '')[:1000]
        error = result.get('error', '')[:500]
        
        self.conversation_history.append({
            "role": "user", 
            "content": f"Command result:\nOutput: {output}\nError: {error}\nReturn code: {result.get('return_code', 0)}"
        })
        
        # Keep conversation history manageable
        if len(self.conversation_history) > 20:
            # Keep first message (original goal) and last 18 messages
            self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-18:]
    
    def update_context_memory(self, command, result):
        """Extract and store important information from command results"""
        
        # Store file counts
        if "find" in command and "wc -l" in command:
            self.context_memory["file_count"] = result.get("output", "").strip()
        
        # Store disk usage
        if command.startswith("df"):
            self.context_memory["disk_usage"] = result.get("output", "")
        
        # Store process info
        if command.startswith("ps"):
            self.context_memory["processes"] = result.get("output", "")
        
        # Store backup status
        if "rsync" in command:
            if result.get("return_code") == 0:
                self.context_memory["backup_status"] = "success"
            else:
                self.context_memory["backup_status"] = "failed"
                
        # Store directory listings
        if command.startswith("ls"):
            self.context_memory["last_listing"] = result.get("output", "")
            
        # Store current working directory
        if command == "pwd":
            self.context_memory["current_directory"] = result.get("output", "").strip()


# Test function
def test_smart_agent():
    """Test the smart agent with sample queries"""
    
    # Check if API key is set
    if not settings.OPENAI_KEY:
        print("❌ Please set OPENAI_API_KEY in your .env file")
        return
    
    agent = SmartAgent()
    
    # Test queries
    test_queries = [
        "check current directory and list files",
        "show system memory and disk usage",
        # "create a test folder and copy a file into it"
    ]
    
    for query in test_queries:
        print(f"\n{'='*50}")
        print(f"Testing: {query}")
        print('='*50)
        
        result = agent.process_smart_workflow(query)
        
        print(f"\nFinal Status: {result['final_status']}")
        if result.get('summary'):
            print(f"Summary: {result['summary']}")
        print(f"Duration: {result.get('duration', 0):.2f} seconds")
        print(f"Steps executed: {len(result['steps'])}")


if __name__ == "__main__":
    # Run test if executed directly
    test_smart_agent()