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

void CameraRotateStrategyParser::Destroy()
{
    curNode_->FreeDoc();
    curNode_->CleanUpParser();
}

} // namespace CameraStandard
} // namespace OHOS