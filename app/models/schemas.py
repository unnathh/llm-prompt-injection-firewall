from pydantic import BaseModel, Field
from typing import List, Optional, Any

class ChatMessage(BaseModel):
    role: str = Field(..., description="The role of the messages author (e.g. system, user, assistant).")
    content: str = Field(..., description="The contents of the message.")

class ChatCompletionRequest(BaseModel):
    model: str = Field(default="gpt-4", description="ID of the model to use.")
    messages: List[ChatMessage] = Field(..., description="A list of messages comprising the conversation so far.")
    temperature: Optional[float] = Field(default=1.0, description="What sampling temperature to use.")
    max_tokens: Optional[int] = Field(default=None, description="The maximum number of tokens to generate.")
