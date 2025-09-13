from typing import List, Literal, Optional, Union
from pydantic import BaseModel

QuestionType = Literal["multiple_choice", "true_false", "short_answer"]


class Question(BaseModel):
    id: str
    type: QuestionType
    prompt: str
    choices: Optional[List[str]] = None
    answer: Union[str, bool]
    explanation: Optional[str] = None


class Quiz(BaseModel):
    topic: str
    difficulty: Literal["beginner", "intermediate", "advanced"]
    questions: List[Question]
