#!/bin/bash
# Copyright 2025 Splunk Inc.
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
poetry run ucc-gen package --path output/demo
