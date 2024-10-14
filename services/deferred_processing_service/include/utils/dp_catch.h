/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_CATCH_H
#define OHOS_CAMERA_DPS_CATCH_H

#define ERROR_CODE() __catch_error_code
#define ERROR_LINE() __catch_error_line
#define ERROR_PROSS() __catch_error_line = __LINE__

#define PROSS                                       \
    int32_t __catch_error_code = 0x7FFFFFCC;        \
    int32_t __catch_error_line = 0x7FFFFFFF;        \
    {
#define END_PROSS                                   \
    }                                               \
    __tabErrorCode:

#define THROW(err)                                  \
    do {                                            \
        __catch_error_code = (err);                 \
        ERROR_PROSS();                              \
        goto __tabErrorCode;                        \
    } while (0)

#define EXEC(func)                                  \
    {                                               \
        if (DP_OK != (__catch_error_code = (func))) \
            THROW(__catch_error_code);              \
    }

#define JUDEG(err, expr)                            \
    {                                               \
        if (!(expr)) {                              \
            THROW(err);                             \
        }                                           \
    }

#define CATCH_ERROR                                 \
    {
#define END_CATCH_ERROR }

#endif // OHOS_CAMERA_DPS_CATCH_H