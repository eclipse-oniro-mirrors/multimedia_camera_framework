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

#ifndef OHOS_CAMERA_DPS_ENABLE_SHARED_CREATE_H
#define OHOS_CAMERA_DPS_ENABLE_SHARED_CREATE_H

#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
template <typename Class>
class EnableSharedCreate {
public:
    virtual ~EnableSharedCreate() = default;

    template <typename... Args>
    static std::shared_ptr<Class> Create(Args&&...args)
    {
        struct MakeSharedHelper : Class {
            explicit MakeSharedHelper(Args&&...args) : Class(std::forward<Args>(args)...) {}
        };

        std::shared_ptr<Class> sharedObj = std::make_shared<MakeSharedHelper>(std::forward<Args>(args)...);
        EnableSharedFromThis(sharedObj, static_cast<EnableSharedCreate*>(sharedObj.get()));
        return sharedObj;
    }

    std::shared_ptr<Class> shared_from_this()
    {
        return std::shared_ptr<Class>(this->weakThis_);
    }

    std::shared_ptr<const Class> shared_from_this() const
    {
        return std::shared_ptr<const Class>(this->weakThis_);
    }

    std::weak_ptr<Class> weak_from_this() noexcept
    {
        return this->weakThis_;
    }

    std::weak_ptr<const Class> weak_from_this() const noexcept
    {
        return this->weakThis_;
    }

protected:
    inline void InitWeakThis(const std::shared_ptr<Class>& weak)
    {
        weakThis_ = weak;
    }

private:
    template<typename X, typename Y>
    friend void EnableSharedFromThis(const std::shared_ptr<X>& sp, Y* base);

    mutable std::weak_ptr<Class> weakThis_;
};

template<typename X, typename Y>
void EnableSharedFromThis(const std::shared_ptr<X>& sp, Y* base)
{
    if (base != nullptr) {
        base->InitWeakThis(sp);
    }
}

template <typename Class>
class EnableSharedCreateInit : public EnableSharedCreate<Class> {
public:
    template <typename... Args>
    static std::shared_ptr<Class> Create(Args&&...args)
    {
        auto sharedObj = EnableSharedCreate<Class>::Create(std::forward<Args>(args)...);
        if (sharedObj && (sharedObj->Initialize() != 0)) {
            sharedObj = nullptr;
        }
        return sharedObj;
    }

    virtual int32_t Initialize() = 0;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_ENABLE_SHARED_CREATE_H