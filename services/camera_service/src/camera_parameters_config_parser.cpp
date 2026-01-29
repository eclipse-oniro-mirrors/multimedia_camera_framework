/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "camera_parameters_config_parser.h"
#include "config_policy_utils.h"
#include "camera_log.h"
#include "camera_util.h"
#include "camera_xml_parser.h"

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
int32_t GetRealConfigPath(const std::string& configFile, std::string& realPath)
{
    char buf[PATH_MAX + 1];
    char* configFilePath = GetOneCfgFile(configFile.c_str(), buf, PATH_MAX + 1);
    char tmpPath[PATH_MAX + 1] = {0};
    CHECK_RETURN_RET_ELOG(!configFilePath || strlen(configFilePath) == 0 || strlen(configFilePath) > PATH_MAX,
        CAMERA_INVALID_STATE, "GetRealConfigPath Failed, configFile:%{public}s", configFile.c_str());
    CHECK_RETURN_RET_ELOG(realpath(configFilePath, tmpPath) == nullptr,
        CAMERA_INVALID_STATE, "GetRealConfigPath Failed, configFile:%{public}s", configFile.c_str());
    realPath = std::string(tmpPath);
    return CAMERA_OK;
}

bool ParseParameterNode(std::shared_ptr<CameraXmlNode> parameterNode, Parameter &parameter)
{
    std::string type;
    parameterNode->GetProp("type", type);
    CHECK_RETURN_RET(!IsUint8Regex(type), false);
    std::string tagName;
    parameterNode->GetProp("tagName", tagName);
    parameter.tagName = tagName;
    parameter.type = static_cast<uint8_t>(std::stoi(type));
    std::map<std::string, std::string> kvPairs;
    for (auto pairNode = parameterNode->GetChildrenNode(); pairNode->IsNodeValid(); pairNode->MoveToNext()) {
        CHECK_CONTINUE(!pairNode->IsElementNode());
        CHECK_CONTINUE(!pairNode->CompareName("kvPair"));
        std::string key;
        std::string value;
        pairNode->GetProp("key", key);
        pairNode->GetProp("value", value);
        CHECK_CONTINUE(key.empty() || value.empty());
        kvPairs[key] = value;
    }
    parameter.kvPairs = kvPairs;
    return true;
}

std::map<std::string, Parameter> CameraParametersConfigParser::ParseXML()
{
    std::map<std::string, Parameter> parameters;
    std::string filePath;
    CHECK_RETURN_RET_ELOG(GetRealConfigPath(PARAMETERS_CONFIG_FILE_PATH, filePath) != CAMERA_OK, parameters,
        "GetRealConfigPath failed!");
    std::shared_ptr<CameraXmlNode> curNode = CameraXmlNode::Create();
    int32_t ret = curNode->Config(filePath.c_str(), nullptr, 0);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, parameters, "Not found camera_parameters_config.xml!");
    CHECK_RETURN_RET(!curNode->CompareName("parameters"), parameters);
    for (auto childNode = curNode->GetChildrenNode(); childNode->IsNodeValid(); childNode->MoveToNext()) {
        CHECK_CONTINUE(!childNode->IsElementNode());
        CHECK_CONTINUE(!childNode->CompareName("parameter"));
        Parameter parameter;
        CHECK_EXECUTE(ParseParameterNode(childNode->GetCopyNode(), parameter),
            parameters[parameter.tagName] = parameter);
    }
    curNode->FreeDoc();
    curNode->CleanUpParser();
    return parameters;
}
} // namespace CameraStandard
} // namespace OHOS