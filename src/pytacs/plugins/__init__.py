import importlib
from typing import List

from structlog.stdlib import BoundLogger

from pytacs.structures.modules import SupportedModule


def load_plugins(plugins_to_load: List[SupportedModule], logger: BoundLogger):
    loaded_modules = {}

    for plugin_name in plugins_to_load:
        # Construct the full module path
        full_module_path: str = f"pytacs.plugins.{plugin_name}"

        try:

            # Dynamically import the module
            module = importlib.import_module(full_module_path)

            # Get the class with the same name as the module
            module_class = getattr(module, plugin_name)

            # Instantiate the class
            instance = module_class()

            # Store the instance in the dictionary
            loaded_modules[plugin_name] = instance

            logger.info(f"Successfully imported and instantiated: {plugin_name}")
        except ImportError:
            logger.exception(f"Failed to import module: {plugin_name}")
        except AttributeError:
            logger.exception(
                f"Failed to find class {plugin_name} in module {full_module_path}"
            )
        except Exception as e:
            logger.exception(
                f"An error occurred while importing {plugin_name}: {str(e)}"
            )

    return loaded_modules
