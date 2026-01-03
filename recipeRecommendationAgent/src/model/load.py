from strands.models import BedrockModel

MODEL_ID = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"

def load_model():
    return BedrockModel(model_id=MODEL_ID)