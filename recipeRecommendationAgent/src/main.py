"""Recipe Bot Agent with Memory Integration."""
import json
import os
from strands import Agent
from bedrock_agentcore import BedrockAgentCoreApp, RequestContext
from bedrock_agentcore.memory import MemoryClient
# from mcp_client.client import get_streamable_http_mcp_client
from model.load import load_model
from long_term_memory_hook import RecipeRecommendationMemoryHookProvider
from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig, RetrievalConfig
from bedrock_agentcore.memory.integrations.strands.session_manager import AgentCoreMemorySessionManager

app = BedrockAgentCoreApp()
log = app.logger

REGION = os.getenv("AWS_REGION")
log.info("REGION: %s", REGION)

REGION="us-east-1"
log.info("REGION set to: %s", REGION)
MEMORY_ID = "RecipeRecommendationAgent_mem-hCDVr5Foji"  # Your created memory ID

memory_client = MemoryClient(region_name=REGION)

# Import AgentCore Gateway as Streamable HTTP MCP Client
# mcp_client = get_streamable_http_mcp_client()
log.info("MCP Client created...")

memory_hook = RecipeRecommendationMemoryHookProvider(MEMORY_ID, memory_client)
log.info("Memory Hook created...")

@app.entrypoint
async def invoke(payload, context: RequestContext):
    """Main entrypoint for the recipe bot agent with memory integration."""

    log.info("--------- inside agent invoke with context: %s", context)
    request_headers = context.request_headers
    app.logger.info("------- Headers: %s", json.dumps(request_headers))

    session_id = getattr(context, 'session_id', 'default')
    log.info("Session ID: %s", session_id)

    # Extract user ID from custom header (headers are lowercase)
    user_id = request_headers.get('x-amzn-bedrock-agentcore-runtime-custom-user-id', 'UNKNOWN')
    log.info("------ User ID from header: %s", user_id)

    # Use header user_id as actor_id for memory operations
    actor_id = user_id
    log.info("------ Actor ID: %s", actor_id)

    # Configure memory
    agentcore_memory_config = AgentCoreMemoryConfig(
        memory_id=MEMORY_ID,
        session_id=session_id,
        actor_id=actor_id
    )

    # Create session manager
    session_manager = AgentCoreMemorySessionManager(
        agentcore_memory_config=agentcore_memory_config,
        region_name=REGION
    )

    print(f"Session manager created for Actor ID: {actor_id}, Session ID: {session_id}")

    
    user_input = payload.get("prompt", "")
    log.info("User Input: %s", user_input)
    # with mcp_client as client:
        # Get MCP Tools
    # tools = client.list_tools_sync()

    # Create agent with memory tools
    agent = Agent(
        model=load_model(),
        system_prompt="""
                        You are a helpful recipe assistant with memory capabilities.
                        Your aim is to provide personalized recipe recommendations based on:

                        1. User's ingredients and preferences
                        2. Past cooking history and feedback
                        3. Dietary restrictions and allergies
                        4. Cooking skill level and equipment

                        Use memory tools to:
                        - Remember user preferences across conversations
                        - Store successful recipes and user feedback
                        - Track dietary restrictions and allergies
                        - Learn from user's cooking patterns

                        Always limit your recommendations to 1 recipe and use tools when appropriate.
                        When you learn something new about the user, save it to memory for future reference.
                    """,
        hooks=[memory_hook],
        tools=[],
        state={"actor_id": actor_id, "session_id": session_id},
        session_manager=session_manager

    )

    response = agent(user_input)
    log.info("Agent Response: %s", response.message["content"][0])
    return response.message["content"][0]["text"]

def format_response(result) -> str:
    """Extract code from metrics and format with LLM response."""
    parts = []

    # Extract executed code from metrics
    try:
        tool_metrics = result.metrics.tool_metrics.get('code_interpreter')
        if tool_metrics and hasattr(tool_metrics, 'tool'):
            action = tool_metrics.tool['input']['code_interpreter_input']['action']
            if 'code' in action:
                parts.append(f"## Executed Code:\n```{action.get('language', 'python')}\n{action['code']}\n```\n---\n")
    except (AttributeError, KeyError):
        pass  # No code to extract

    # Add LLM response
    parts.append(f"## Result:\n{str(result)}")
    return "\n".join(parts)

if __name__ == "__main__":
    app.run()