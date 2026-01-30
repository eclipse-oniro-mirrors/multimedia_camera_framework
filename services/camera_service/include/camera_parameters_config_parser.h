/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CAMERA_PARAMETERS_CONFIG_PARSER_H
#define CAMERA_PARAMETERS_CONFIG_PARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

#include "camera_xml_parser.h"

namespace OHOS {
namespace CameraStandard {

struct Parameter {
    std::string tagName;
    uint8_t type;
    std::map<std::string, std::string> kvPairs;
};

class CameraParametersConfigParser {
public:
    const std::string PARAMETERS_CONFIG_FILE_PATH = "etc/camera/camera_parameters_config.xml";

    CameraParametersConfigParser() = default;
    ~CameraParametersConfigParser() = default;
    std::map<std::string, Parameter> ParseXML();
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PARAMETERS_CONFIG_PARSER_H