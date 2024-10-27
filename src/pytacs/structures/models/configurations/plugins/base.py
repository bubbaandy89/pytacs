from pytacs.structures.models.base import BaseModel


class PluginConfiguration(BaseModel):
    plugin_name: str
    enabled: bool = True
