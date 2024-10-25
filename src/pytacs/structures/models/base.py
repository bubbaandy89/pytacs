from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict


class BaseModel(PydanticBaseModel):
    """
    Default base model for the pytacs models
    """

    model_config = ConfigDict(
        frozen=True, arbitrary_types_allowed=True, use_enum_values=True
    )
