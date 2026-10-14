#!/bin/bash
set -euo pipefail

# Copyright 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
poetry install
poetry build
poetry run ucc-gen build \
  --source=tests/integration/demo/package \
  --config=tests/integration/demo/globalConfig.json \
  --ta-version=0.0.1
poetry run pip install dist/*.whl --target output/demo/lib
# urllib3 is supplied by Splunk Core at runtime. Remove the dependency pulled
# in by the library wheel so this integration package exercises that behavior.
poetry run python -c 'from pathlib import Path; import shutil; [shutil.rmtree(path) for path in Path("output/demo/lib").glob("urllib3*") if path.is_dir()]'
test ! -e output/demo/lib/urllib3
test ! -e output/demo/lib/urllib3-*.dist-info
poetry run ucc-gen package --path output/demo
