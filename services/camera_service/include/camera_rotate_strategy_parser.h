/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef CAMERA_ROTATE_STRATEGY_PARSER_H
#define CAMERA_ROTATE_STRATEGY_PARSER_H

#include <unordered_map>
#include <string>
#include <sstream>

#include "camera_log.h"
#include "parser.h"
#include "camera_xml_parser.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;

class CameraRotateStrategyParser : public Parser {
public:
    void Destroy() final;

    CameraRotateStrategyParser()
    {
        curNode_ = CameraXmlNode::Create();
        MEDIA_DEBUG_LOG("CameraRotateStrategyParser ctor");
    }

    ~CameraRotateStrategyParser()
    {
        MEDIA_DEBUG_LOG("CameraRotateStrategyParser dtor");
        Destroy();
        curNode_ = nullptr;
    }

private:
    std::shared_ptr<CameraXmlNode> curNode_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_ROTATE_STRATEGY_PARSER_H