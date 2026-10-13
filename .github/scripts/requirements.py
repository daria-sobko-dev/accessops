"""Print the dependencies from pyproject.toml (one list to maintain): main + dev."""

import tomllib

with open("pyproject.toml", "rb") as handle:
    project = tomllib.load(handle)["project"]
print("\n".join(project["dependencies"] + project["optional-dependencies"]["dev"]))
