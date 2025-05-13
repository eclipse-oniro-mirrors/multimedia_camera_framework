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

#include "camera_rotate_strategy_parser.h"
#include "camera_log.h"
#include "camera_util.h"

namespace OHOS {
namespace CameraStandard {
static const int8_t DECIMAL = 10;
// LCOV_EXCL_START
bool CameraRotateStrategyParser::LoadConfiguration()
{
    curNode_ = CameraXmlNode::Create();
    int32_t ret = curNode_->Config(DEVICE_CONFIG_FILE, nullptr, 0);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("Not found camera_rotate_strategy.xml!");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(strategyInfosMutex_);
        cameraRotateStrategyInfos_.clear();
    }
    bool result = ParseInternal(curNode_->GetCopyNode());
    CHECK_ERROR_RETURN_RET_LOG(!result, false, "Camera rotate strategy xml parse failed.");
    return true;
}

void CameraRotateStrategyParser::Destroy()
{
    curNode_->FreeDoc();
    curNode_->CleanUpParser();
}

bool CameraRotateStrategyParser::ParseInternal(std::shared_ptr<CameraXmlNode> curNode)
{
    for (; curNode->IsNodeValid(); curNode->MoveToNext()) {
        if (!curNode->IsElementNode()) {
            continue;
        }
        if (curNode->CompareName("strategy")) {
            ParserStrategyInfo(curNode->GetCopyNode());
        } else {
            ParseInternal(curNode->GetChildrenNode());
        }
    }
    return true;
}

void CameraRotateStrategyParser::ParserStrategyInfo(std::shared_ptr<CameraXmlNode> curNode)
{
    std::lock_guard<std::mutex> lock(strategyInfosMutex_);
    if (curNode->IsNodeValid() && curNode->IsElementNode()) {
        CameraRotateStrategyInfo info = {};
        curNode->GetProp("bundleName", info.bundleName);

        std::string pValue;
        float wideValue = -1.0;
        curNode->GetProp("wideValue", pValue);
        char* endPtr;
        wideValue = std::strtof(pValue.c_str(), &endPtr);
        if (*endPtr != '\0' || pValue.empty()) {
            MEDIA_ERR_LOG("The wideValue parameter is invalid.");
            wideValue = -1.0;
        }
        info.wideValue = wideValue;
        endPtr = nullptr;

        int32_t rotateDegree = -1;
        curNode->GetProp("rotateDegree", pValue);
        long result = strtol(pValue.c_str(), &endPtr, DECIMAL);

        if (*endPtr != '\0' || pValue.empty()) {
            MEDIA_ERR_LOG("The rotateDegree parameter is invalid.");
            rotateDegree = -1;
        } else {
            rotateDegree = static_cast<int32_t>(result);
        }
        info.rotateDegree = rotateDegree;

        int16_t fps = -1;
        curNode->GetProp("fps", pValue);
        endPtr = nullptr;
        result = strtol(pValue.c_str(), &endPtr, DECIMAL);

        if (*endPtr != '\0' || pValue.empty()) {
            MEDIA_ERR_LOG("The fps parameter is invalid.");
            fps = -1;
        } else {
            fps = static_cast<int16_t>(result);
        }
        info.fps = fps;
        cameraRotateStrategyInfos_.push_back(info);
        MEDIA_INFO_LOG("ParserStrategyInfo: bundleName:%{public}s, wideValue:%{public}f, "
            "rotateDegree:%{public}d, fps:%{public}d",
            info.bundleName.c_str(), info.wideValue, info.rotateDegree, info.fps);
    }
}// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS
