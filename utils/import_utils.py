from utils.startup_text import module_startup_text
import importlib

def auto_import(module_name):
    module_startup_text(module_name)
    return importlib.import_module(module_name)
