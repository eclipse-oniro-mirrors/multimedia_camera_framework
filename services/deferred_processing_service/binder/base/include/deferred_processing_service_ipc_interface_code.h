/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_IPC_INTERFACE_CODE_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_IPC_INTERFACE_CODE_H

/* SAID: 3008 */
namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
/**
 * @brief Deferred processing service callback remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum DeferredProcessingServiceCallbackInterfaceCode {
    DPS_PHOTO_CALLBACK_PROCESS_IMAGE_DONE = 0,
    DPS_PHOTO_CALLBACK_ERROR,
    DPS_PHOTO_CALLBACK_STATE_CHANGED
};

/**
 * @brief Deferred processing service remote request code for IPC.
 *
 * @since 1.0
 * @version 1.0
 */
enum DeferredProcessingServiceInterfaceCode {
    DPS_BEGIN_SYNCHRONIZE = 0,
    DPS_END_SYNCHRONIZE,
    DPS_ADD_IMAGE,
    DPS_REMOVE_IMAGE,
    DPS_RESTORE_IMAGE,
    DPS_PROCESS_IMAGE,
    DPS_CANCEL_PROCESS_IMAGE
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_IPC_INTERFACE_CODE_H