# Camera Framework 项目宪法 (AGENTS.md)

## 1. 项目定位

Camera Framework 是华为鸿蒙操作系统的核心多媒体组件，负责相机设备的全生命周期管理、图像捕获、视频录制、照片/视频分段式后处理、媒体流实时处理及网络相机资源管理，为第三方应用、系统应用和 C/C++ 开发者提供完整的相机系统能力。

### 技术栈

| 维度 | 说明 |
|------|------|
| **编程语言** | C++（主要实现语言）、C（NDK 接口）、ArkTS（NAPI 接口）、仓颉（CJ FFI 绑定）、Taihe/ANI 绑定 |
| **架构模式** | 五层分层架构（common → dynamic_libs → interfaces → frameworks → services）+ 3 个独立子系统 |
| **通信机制** | Binder IPC（跨进程通信）、HDI 接口（硬件驱动接口 V1_0~V1_7） |
| **系统服务** | SystemAbility、HiLog、HiSysEvent、HiTrace |
| **设计模式** | 工厂模式、单例模式、适配器模式、观察者模式、命令模式、状态机模式、代理模式、RAII |
| **命名空间** | `OHOS::CameraStandard`（通用）、`OHOS::CameraStandard::DeferredProcessing`（延迟处理） |

### 主要功能模块

1. **相机设备管理**：多相机设备管理、状态监听、能力查询、优先级调度与并发控制
2. **捕获会话管理**：照片/视频/扫描/安全相机/控制中心/Mech/Pose/智能捕获等会话类型
3. **输出管理**：照片/视频/预览/元数据/深度数据/电影文件输出
4. **分段式处理**：照片和视频的分段式后处理，基于系统状态智能调度
5. **媒体流处理**：音视频流管道+过滤器架构，支持多路并行和分段式后处理
6. **系统级扩展**：20+ 种专业拍摄模式（夜景/人像/专业/全景/微距/慢动作等）和 AI 引导拍摄
7. **网络相机**：网络相机资源下载与本地管理

### 应用场景

- 移动设备相机应用开发（系统相机、第三方相机应用）
- 视频会议和直播应用
- 扫码和 OCR 应用
- 安全相机应用
- 网络相机应用（远程相机资源访问）
- AI 引导拍摄（灵感智拍、构图建议、姿态建议）

### 按任务类型定位代码

| 任务类型 | 首选目录 | 关键文件 |
| --- | --- | --- |
| 新增/修改会话模式（照片/视频/扫描/安全/Mech/Pose/智能捕获） | `frameworks/native/camera/base/src/session/` | `capture_session.cpp`、`photo_session.cpp`、`video_session.cpp`、`scan_session.cpp`、`secure_camera_session.cpp`、`mech_session.cpp`、`intelli_capture_session.cpp` |
| 修改会话状态机 | `services/camera_service/include/`、`services/camera_service/idls/` | `hcapture_session.h`（`StateMachine`）、`CameraTypes.idl`（`CaptureSessionState`） |
| 修改相机设备生命周期 | `frameworks/native/camera/base/src/input/`、`services/camera_service/src/` | `camera_device.cpp`、`camera_manager.cpp`、`hcamera_device.cpp`、`hcamera_host_manager.cpp` |
| 修改输出（照片/视频/预览/元数据/电影文件） | `frameworks/native/camera/base/src/output/`、`services/camera_service/src/` | `photo_output.cpp`、`photo_output_callback.cpp`、`video_output.cpp`、`preview_output.cpp`、`metadata_output.cpp`、`hstream_capture.cpp`、`hstream_repeat.cpp` |
| 修改 IPC 接口/跨进程通信 | `services/camera_service/idls/`、`services/deferred_processing_service/idls/` | `ICameraService.idl`、`ICaptureSession.idl`、`CameraTypes.idl` 及各 `I*.idl` |
| 修改 NDK C 接口 | `frameworks/native/ndk/`、`interfaces/kits/native/include/camera/` | `camera.h` 及各对象头文件（`capture_session.h`、`photo_output.h` 等） |
| 修改 NAPI/系统 API 绑定 | `frameworks/js/camera_napi/`、`frameworks/js/camera_napi_for_sys/`、`interfaces/kits/js/` | `camera_napi.h`、各 `*_napi.cpp` |
| 修改分段式后处理（DPS） | `services/deferred_processing_service/` | `deferred_photo_processing_session.cpp`、`deferred_video_processing_session.cpp` |
| 修改 HDI 硬件交互/版本兼容 | `services/camera_service/src/` | `hcamera_host_manager.cpp`、`hstream_operator.cpp`、`hstream_capture.cpp`、`hcamera_device.cpp` |
| 修改媒体流管道/过滤器 | `mediastream/` | `include/filter/`、`include/pipeline/`、`src/` |
| 修改动态库适配层 | `dynamic_libs/` | `av_codec/`、`media_library/`、`image_effect/` 等 |
| 修改网络相机引擎 | `camera_network_engine/` | `include/network_client/`、`include/resource_manager_utils/` |
| 修改权限校验/鉴权 | `services/camera_service/src/`、`frameworks/native/camera/base/src/utils/` | `camera_util.cpp`（`CheckPermission`）、`camera_security_utils.cpp`、`camera_privacy.cpp` |
| 修改 DFX（日志/事件/追踪/超时） | `common/utils/` | `camera_log.h`（`MEDIA_*_LOG`、`CAMERA_SYSEVENT_*`、`CAMERA_SYNC_TRACE`） |

## 2. 项目宪法

### 2.1 架构约束

1. **分层职责分离**：interfaces 仅定义接口契约不含实现；frameworks 实现核心逻辑不含 IPC；services 提供 Stub 实现不含客户端逻辑；common 仅提供基础设施不含业务逻辑。
2. **语言绑定独立**：NDK 层与 NAPI 层各自独立实现语言绑定，共享底层框架类但不互相调用。
3. **接口隔离**：上层模块不直接 `dlopen` 外部库，统一通过 dynamic_libs 的 Proxy 适配层访问。
4. **HDI 版本兼容**：支持 HDI Camera Host V1_0 至 V1_7 共 8 个版本，HStreamOperator 兼容 v1_0 至 v1_5。
5. **多用户隔离**：分段式处理按 userId 隔离，每个用户拥有独立的处理管线和作业队列。

### 2.2 编码约束

1. **命名空间**：使用 `OHOS::CameraStandard`（通用）或 `OHOS::CameraStandard::DeferredProcessing`（延迟处理），不使用匿名命名空间。
2. **类命名**：服务端类以 `H` 前缀（如 `HCameraService`），接口类以 `I` 前缀，代理类以 `Proxy` 后缀，NAPI 类以 `Napi` 后缀，NDK 实现类以 `Impl` 后缀。
3. **智能指针**：使用 `sptr<T>`/`wptr<T>` 管理对象生命周期，避免循环依赖（Output 持有 Session 的 `wptr` 弱引用）。
4. **错误码**：通用错误码（0/201/202/401）、相机操作错误码（7400101~7400114）、服务错误码（7400201），通过 `errorCodeMap` 映射表转换。
5. **DFX**：使用 hilog 分级日志、hisysevent 事件上报、hitrace 性能追踪、CameraXCollie 超时检测。
6. **线程安全**：回调管理使用互斥锁保护，NAPI 异步任务串行化执行（超时 2000ms），跨线程回调通过 `uv_async_send` 切换到 JS 线程。
7. **项目宏复用**：日志和判空复用 `common/utils/camera_log.h` 中的宏（`MEDIA_DEBUG_LOG`/`MEDIA_INFO_LOG`/`MEDIA_ERR_LOG` 等 `camera_log.h:43-47`，`CHECK_RETURN_ELOG`/`CHECK_RETURN_RET_ELOG` 等 `camera_log.h:123-185`），事件上报复用 `CAMERA_SYSEVENT_*`（`camera_log.h:281-314`），不要重新实现等价功能。
8. **日志域**：相机框架使用 `LOG_DOMAIN 0xD002B01`（`camera_log.h:27`）、`LOG_TAG "CAMERA"`；分段式处理服务使用 `0xD002B02`（`dp_log.h:27`），不要混用其他日志域。
9. **错误码转换**：内部细分错误码（`InnerErrorCode` 74001021~74002017，`camera_error_code.h:56-72`）必须经 `errorCodeMap`/`GetCameraErrorCode`（`camera_error_code.h:74-96`）映射为公共 `CameraErrorCode`（7400101~7400201）后再返回上层，不要直接透传内部码给应用。
10. **会话状态机**：`CaptureSessionState`（`SESSION_INIT`→`CONFIG_INPROGRESS`→`CONFIG_COMMITTED`→`STARTED`→`RELEASED`，`CameraTypes.idl:63`）由 `StateMachine`（`hcapture_session.h:75-103`）管理，状态迁移必须经 `Transfer`/`CheckTransfer`，禁止绕过状态机直接改 `currentState_`。

### 2.3 性能约束

- **帧回调为高频路径**：`OnBufferAvailable`（`photo_output_callback.cpp:341`、`metadata_output.cpp:553`、`composition_feature.cpp:249`）、`OnFrameAvailable` 等回调在每帧触发，禁止在其中添加同步 IPC、字符串格式化、INFO 及以上级别日志或全量扫描。
- **回调内禁止耗时操作**：帧数据处理应转发到 TaskManager 异步执行（参考 `PhotoNativeConsumer` 通过 listener `ExecuteOnBufferAvailable` 异步处理，`photo_output_callback.cpp:357`）。
- **NAPI 异步任务串行化**：使用 `napi_create_async_work` + `napi_queue_async_work_with_qos`（`camera_session_napi.cpp`、`photo_output_napi.cpp` 等），不要在回调线程同步等待业务结果。
- **HDI 版本判断避免重复查询**：`GetVersionId` 结果应缓存，`CAST_IF_VERSION_GT`（`hcamera_host_manager.cpp:299-312`）已封装版本向下兼容分支，不要在每帧路径重复获取版本号。

### 2.4 公共 API 约束

**Do not（禁止）：**
- 修改已发布 NDK C API（`interfaces/kits/native/include/camera/*.h`）的函数签名、参数个数/顺序/类型、返回值类型
- 修改 `Camera_ErrorCode` 枚举值（7400101~7400201，`camera.h:67-140`）或删除已有枚举项
- 修改 NAPI 错误码映射表 `mapCameraErrorCode`（`camera_napi.h:280-295`）
- 删除或重命名已发布公共 API（带 `@since 11/12/26.0.0` 标注的接口）
- 修改已有 API 行为语义（如异步变同步、阻塞变非阻塞、错误码含义变更）

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要 `CheckPermission` 权限校验、`MEDIA_*_LOG` 日志、`CAMERA_SYSEVENT_*` 事件上报、`@since` 版本标注
- 新增系统 API（`frameworks/js/camera_napi_for_sys/`）：确认系统应用权限（202）检查逻辑
- 修改 inner API（`interfaces/inner_api/`）：评估是否影响 NDK/NAPI/仓颉等多语言绑定兼容性
- 修改 `Camera_ErrorCode` 错误处理逻辑：确认是否影响应用层错误码兼容性

### 2.5 安全与权限边界

**Do not（禁止）：**
- 绕过 `CheckPermission`（`camera_util.cpp:394`，基于 `AccessTokenKit::VerifyAccessToken`）权限校验
- 绕过 `CheckPermissionBeforeOpenDevice`（`hcamera_device.cpp:677`）直接打开相机设备
- 用缓存的 token 代替 `IPCSkeleton::GetCallingTokenID()` 实时取调用方 token 进行鉴权（`hcamera_service.cpp:1144/1352/4730` 等均在调用入口取 token）
- 在日志中打印敏感信息（拍照内容、人脸元数据、token 等）；`MEDIA_*_LOG` 中 `%{public}` 默认公开，敏感字段须用 `%{private}`
- 修改 DPS 多用户隔离逻辑：分段式处理按 `userId_` 隔离处理管线和作业队列（`deferred_photo_processing_session.cpp`、`deferred_video_processing_session.cpp`、各 command 均以 `userId_` 为 key，`DPS_SendCommand<XXXCommand>(userId_, ...)`）
- 修改安全相机（SecureCamera）相关隐私状态上报（`camera_privacy.cpp` 的 `CameraUseStateChangeCb::StateChangeNotify`）未经安全评审

**Ask before（修改前必须确认）：**
- 涉及 `ohos.permission.CAMERA` / `CAMERA_BACKGROUND` / `CAMERA_CONTROL` / `CAMERA_SHARED` / `MANAGE_CAMERA_CONFIG` / `MICROPHONE` 权限常量的改动（`hstream_capture.cpp:1847`、`hcamera_service.cpp:1365/2794/3512` 等）
- 涉及 `CheckPermissionForBroker`（`hcamera_service.cpp:5224`）等特权/代理判断的改动
- 涉及安全相机、隐私态、防窥屏等安全特性的改动
- 涉及跨用户数据（按 `userId` 隔离的图片/视频资源）访问逻辑的改动

### 2.6 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 IDL 文件（`services/camera_service/idls/*.idl`、`services/deferred_processing_service/idls/*.idl`）中已有方法的 `[ipccode N]` 编号（如 `ICameraService.idl` `[ipccode 0..25]`、`ICaptureSession.idl` `[ipccode 0..49]`）
- 修改 IDL 中已有方法的参数个数、顺序、类型（破坏 `MessageParcel` 序列化兼容）
- 修改 `CameraTypes.idl` 中已有枚举值或 `struct` 字段顺序（如 `CaptureSessionState`、`EffectParam`、`MetadataObjectType`）
- 修改 HDI 版本判断的降级行为：`GetVersionId(major, minor) >= HDI_VERSION_ID_1_X` 分支（`hstream_operator.cpp:1682/1930/2615`、`hcapture_session` 间接、`hcamera_host_manager.cpp:329-343`）控制各版本能力可用性

**Ask before（修改前必须确认）：**
- 新增 IPC 接口：必须追加新的 `[ipccode N]`（不能复用/插入已有编号），确认跨版本与跨进程兼容
- 新增 HDI 版本分支：确认对旧版本设备的降级行为是否完整
- 修改跨进程传递的数据结构：评估 `Parcel` 序列化前后兼容性

### 2.7 生成代码边界

**Do not（禁止）：**
- 手动编辑 IDL 编译器生成的 Proxy/Stub 代码（编译产物目录下 `*_proxy.cpp`/`*_stub.cpp` 及对应头文件）
- 直接修改 HDI 接口头文件（`HDI::Camera::V1_0`~`V1_7` 由 HDI 工具生成）

**正确做法：**
- 修改 `services/*/idls/*.idl` 定义文件后重新编译生成代码
- 修改 `CameraTypes.idl` 共享类型定义
- 生成代码不满足需求时，调整 IDL 定义或使用回调机制（`I*Callback` 接口）

### 2.8 设备操作约束

**涉及真实相机硬件时的注意事项：**
- 不执行可能影响设备正常运行的破坏性操作（如强制关闭相机、跳过 `Release`/`delayedClose` 流程，`hcamera_device.cpp:599/1165`）
- 相机设备生命周期遵循 Open → 使用 → Close/Release 顺序，延迟关闭走 `delayedClose`（`hcamera_device.cpp:599`）
- HDI 交互返回的 `CamRetCode` 必须转换为 `CameraErrorCode` 后再返回上层，禁止直接透传 HDI 错误码给应用
- 涉及相机硬件的改动需提供板侧证据（`hilog`/`hitrace` 输出、截图或 `hdc` 输出）

### 2.9 必须遵守的约束（红线清单）

- **禁止**在 interfaces 模块中编写 .cpp 实现代码
- **禁止**在 frameworks 层直接处理 Binder 序列化/反序列化逻辑
- **禁止**在 NDK 层与 NAPI 层之间直接互相调用
- **禁止**上层模块直接 dlopen 外部库，必须通过 Proxy 适配层
- **禁止**在会话运行期间添加或移除输入/输出（返回 7400105）
- **禁止**在未获取相机权限的情况下枚举或打开相机设备（返回 201）

## 架构及依赖

### 核心架构原则

1. **分层架构**:
   - 基础设施层(common):提供任务调度、定时器、动态库加载、代理适配等基础能力
   - 动态适配层(dynamic_libs):封装外部多媒体系统库,采用适配器模式和插件化架构
   - 接口合同层(interfaces):定义全部接口契约,不含实现逻辑
   - 框架实现层(frameworks):实现接口层定义的API,提供核心业务逻辑
   - 服务实现层(services):提供系统级服务,通过Binder IPC通信

2. **模块化设计**:
   - 高度模块化,各模块职责清晰
   - 插件化架构,支持动态加载和扩展
   - 接口隔离,降低模块耦合度

### 设计实现方式

1. **对象创建管理**:CameraAbilityBuilder采用工厂模式封装复杂对象构建过程,CFilterFactory采用工厂模式统一管理各种过滤器的创建并支持自动注册
2. **全局实例管理**:HCameraSessionManager、CFilterFactory、DeferredProcessingService采用单例模式提供全局唯一的服务实例
3. **接口适配**:AvCodecAdapter采用适配器模式统一不同编解码库的接口,MovingPhotoAdapter采用适配器模式隔离动态照片处理依赖
4. **事件通知**:各种Callback接口实现观察者模式,支持相机状态变化、照片处理完成等事件通知
5. **数据流处理**:Pipeline采用管道模式实现媒体流数据的多阶段处理
6. **功能扩展**:MovieFile Plugin采用插件模式实现功能模块的动态扩展
7. **跨进程通信**:各种Proxy类采用代理模式实现跨进程通信和接口适配

### 外部依赖

1. **系统依赖**:
   - hilog:日志系统
   - hisysevent:系统事件
   - hitrace:性能追踪
   - bundlefw:包管理框架
   - samgr:系统服务管理

2. **多媒体依赖**:
   - av_codec:音视频编解码
   - image_effect:图像效果
   - image_framework:图像框架
   - media_library:媒体库
   - surface:显示缓冲区

3. **网络依赖**:
   - curl:网络客户端
   - network:网络通信

4. **其他依赖**:
   - c_utils:C语言工具库
   - ipc_utils:IPC工具库
   - graphic:图形库

## 目录结构

```
camera_framework/
├── common/                      # 公共工具库和基础设施组件,提供动态库加载、日志管理、任务调度等基础功能
│   ├── include/task_manager/    # 任务管理器接口,提供异步任务管理能力
│   ├── include/timer/           # 定时器接口,提供定时和超时管理能力
│   ├── src/                     # 公共模块实现代码,包含task_manager和timer的实现
│   └── utils/                   # 通用工具类和代理类,包含动态加载器、日志接口、定时器等
│
├── dynamic_libs/                # 动态加载库和适配层,封装外部媒体库并提供统一接口
│   ├── av_codec/                # 音视频编解码适配器,统一不同编解码库的接口
│   ├── camera_notification/     # 相机通知服务适配器,提供系统通知服务
│   ├── dfx/                     # 可靠性分析工具适配器,提供性能分析和故障诊断能力
│   ├── image_effect/            # 图像效果处理适配器,封装图像效果库
│   ├── image_framework/         # 图像框架适配器,提供图像处理能力
│   ├── media_library/           # 媒体库适配器,提供媒体文件管理能力
│   ├── media_manager/           # 媒体管理器适配器,提供媒体流管理能力
│   ├── moving_photo/            # 动态照片处理适配器,封装动态照片处理功能
│   ├── watermark_exif_metadata/ # 水印和EXIF元数据适配器,提供水印和元数据管理
│   └── xcomponent_controller/   # XComponent控制器适配器,提供组件控制能力
│
├── frameworks/                  # 框架核心实现层,实现接口层定义的API并提供核心业务逻辑
│   ├── native/camera/base/      # 原生相机基础框架,实现相机设备管理、捕获会话、输出管理等核心功能
│   │   ├── src/ability/         # 相机能力处理模块,负责相机设备能力的查询和管理
│   │   ├── src/deferred_proc_session/  # 分段式处理会话,提供照片和视频的分段式后处理能力
│   │   ├── src/input/           # 输入设备管理,实现相机设备的创建和生命周期管理
│   │   ├── src/output/          # 输出管理,实现照片输出、视频输出、元数据输出等
│   │   ├── src/resource/        # 资源管理,实现相机资源的管理和调度
│   │   ├── src/session/         # 会话管理,实现照片会话、视频会话、扫描会话等多种会话类型
│   │   └── src/utils/           # 工具类,提供辅助功能和工具方法
│   ├── native/camera/extension/ # 扩展功能,提供相机框架的扩展能力
│   ├── native/ndk/              # NDK接口实现,提供C语言风格的API接口
│   ├── js/camera_napi/          # JS NAPI接口实现,提供ArkTS可访问的API
│   ├── js/camera_napi_for_sys/  # 系统API的JS NAPI接口实现,提供系统级ArkTS可访问的API
│   ├── cj/                      # 仓颉语言接口实现,提供仓颉语言绑定的API
│   └── taihe/                   # 鸿蒙Taihe框架实现,提供Taihe框架的接口支持
│
├── interfaces/                  # 接口定义层,定义相机功能的标准API接口
│   ├── inner_api/native/camera/include/  # 内部原生API接口,提供C++风格的内部接口
│   │   ├── abilities/            # 相机能力集接口,定义相机设备能力集合查询接口
│   │   ├── ability/              # 相机能力接口,定义相机设备能力查询接口
│   │   ├── output/               # 输出接口,定义照片、视频、元数据等输出接口
│   │   ├── input/                # 输入接口,定义相机设备管理接口
│   │   ├── session/              # 会话接口,定义各种捕获会话接口
│   │   ├── resource/             # 资源接口,定义相机资源管理接口
│   │   └── deferred_proc_session/        # 分段式处理接口,定义分段式处理会话接口
│   └── kits/                    # 外部API接口,提供给应用开发者的公共接口
│       ├── native/              # NDK接口,提供C语言风格的外部接口
│       └── js/                  # JS NAPI接口,提供ArkTS语言的外部接口
│
├── services/                    # 服务实现层,提供系统级服务并使用Binder IPC通信
│   ├── camera_service/          # 相机主服务,实现相机设备管理、会话管理等核心服务
│   │   ├── binder/              # Binder通信实现,提供跨进程通信能力
│   │   ├── idls/                # IDL接口定义,定义跨进程通信的接口描述
│   │   ├── include/             # 服务接口定义,定义服务端接口
│   │   └── src/                 # 服务实现代码,实现相机服务核心逻辑
│   └── deferred_processing_service/      # 分段式处理服务,提供分段式处理的后台服务
│       ├── idls/                # IDL接口定义,定义分段式处理跨进程通信的接口描述
│       ├── include/             # 服务接口定义,定义分段式处理服务端接口
│       └── src/                 # 服务实现代码,实现分段式处理服务核心逻辑
│
├── mediastream/                 # 媒体流处理模块,提供流水线处理和过滤器功能
│   ├── include/filter/          # 过滤器接口,定义各种媒体流处理过滤器
│   ├── include/pipeline/        # 管道接口,定义媒体流处理管道
│   └── src/                     # 过滤器和管道实现,实现具体的媒体流处理逻辑
│
├── moviefile/                   # 电影文件处理模块,提供电影文件读写和处理功能
│   ├── include/movie_file/      # 电影文件接口,定义电影文件读写接口
│   └── include/plugin/          # 插件系统,提供电影文件处理插件
│
├── camera_network_engine/       # 相机网络引擎,提供网络相机访问和远程控制功能
│   ├── include/network_client/  # 网络客户端接口,定义RTSP、HTTP、WebSocket等网络客户端
│   └── include/resource_manager_utils/  # 资源管理工具,提供网络资源管理和调度
│
└── test/                        # 测试代码,包含模糊测试和通用测试工具
    ├── fuzztest/                # 模糊测试,测试框架的健壮性和安全性
    └── test_common/             # 通用测试工具,提供测试辅助功能和公共fixture
```

### 目录依赖关系

```
interfaces (接口定义层)
    ↓
    └──> frameworks (框架实现层)
            ↓
            ├──> services (服务实现层)
            │       ├──> dynamic_libs (动态加载库)
            │       └──> mediastream (媒体流处理)
            │               └──> moviefile (电影文件处理)
            │
            ├──> common (公共工具库)
            │       └──> dynamic_libs (动态加载库)
            │
            └──> camera_network_engine (网络引擎)
                    └──> common (公共工具库)
```

### 编译命令

```bash
NextBuild --cache ./build_system.sh --abi-type generic_generic_arm_64only --device-type general_all_phone_standard --ccache --build-variant root --gn-flags=--export-compile-commands -j50 --gn-args use_cfi=false --gn-args allow_sanitize_debug=true --disable-post-build --gn-args fwk_no_hidden=true --build-target camera_utils foundation/multimedia/camera_framework/frameworks/native/camera/base:camera_framework camera_framework_ex ohcamera camerapicker_napi camera_napi camera_napi_base camera_napi_ex camera_dynamic_avcodec camera_dynamic_medialibrary camera_dynamic_media_manager camera_dynamic_moving_photo camera_dynamic_picture media_stream camera_service camera_service_ext deferred_processing_service camera_framework_test
```

### 验证命令

| 场景 | 命令 | 说明 |
|------|------|------|
| **全量编译** | 见上方编译命令 | 编译全部目标 |
| **增量编译** | 去掉 `--cache` 参数 | 仅编译变更文件 |
| **清理后编译** | 在编译命令前加 `clean` | 清理 build 目录后重新编译 |
| **单元测试** | 编译 `camera_framework_test` 目标后执行 | 测试框架核心功能 |
| **模糊测试** | 编译 `test/fuzztest/` 下的 fuzz 目标 | 测试框架健壮性和安全性 |

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述编译命令，无新增 ERROR
3. **相关测试通过** - `camera_framework_test` 单元测试通过；涉及 IPC Stub 的改动需通过对应 fuzz 目标
4. **板侧验证（如适用）** - 涉及相机硬件/HDI/预览/拍照/录制的改动需提供板侧证据（`hilog`/`hitrace`/截图/`hdc` 输出）
5. **文档更新（如适用）** - 公共 API（NDK/NAPI）修改需同步更新头文件注释与 `@since` 版本标注

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分（如板侧相机实拍验证、多用户隔离回归）。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、HDI 版本兼容性、性能/安全风险）、未完成事项。

### 构建产物

| 产物 | 说明 |
|------|------|
| `libcamera_framework.z.so` | 核心客户端框架库 |
| `libcamera_service.z.so` | 相机主服务库 |
| `libcamera_napi.z.so` | 公共 NAPI 接口库 |
| `libcamera_napi_for_sys.z.so` | 系统级 NAPI 接口库 |
| `libohcamera.z.so` | NDK C 接口库 |
| `libcamera_dynamic_*.z.so` | 动态适配库（avcodec/medialibrary/moving_photo 等） |
| `libmedia_stream.z.so` | 媒体流处理库 |
| `libdeferred_processing_service.z.so` | 分段式处理服务库 |

## 3. 知识路由表

项目知识存放在 `docs/knowledge/` 目录下，采用**二级索引**实现渐进式披露：

- **一级索引**（本文件）：按场景路由到顶层知识文档
- **二级索引**（`glossary.md`）：术语 → entity 文件的详细指引

### 3.1 知识文件加载规则

| 层级 | 知识文件 | 说明 | 加载时机 |
|------|---------|------|---------|
| **必加载** | `glossary.md` | 术语表 + entities 二级索引（每个术语带 → entity 文件链接） | **启动时** |
| **必加载** | `business-context.md` | 业务背景、产品定位、角色边界、外部依赖 | **启动时** |
| **按需** | `architecture.md` | 架构设计及约束、分层架构、处理链路、数据流向 | **开发代码时** |
| **按需** | `coding-standards.md` | 编码规范、命名、设计模式、内存管理、错误码、DFX、线程安全 | **开发代码时** |
| **按需** | `entities/*.md` | 业务实体详细知识（一实体一文件） | **glossary 二级索引指引** |
| **按需** | `technologies/*.md` | 平台技术框架知识 | **场景路由指引** |

### 3.2 术语查询流程

1. 查 `glossary.md` 获取术语定义 + → entity 文件链接
2. 点击链接加载对应 entity 文件获取详细知识
3. glossary 和 entities 中均无该术语时，使用 `harmonyos-knowledge-management-tool` 从 `docs/LLM-wiki` 查询

### 3.3 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别（参照"按任务类型定位代码"表）
2. 根据场景路由表确定需要阅读的文档
3. 根据本文件"项目宪法"（2.1~2.9）确认不违反任何约束，特别是公共 API、安全/权限、协议兼容、生成代码边界
4. 声明："我将修改 X，已阅读 Y 文档，遵循 Z 约束"

### 3.4 场景路由索引

以下按工作场景路由到所需知识文件。entities 层面的具体文件通过 `glossary.md` 二级索引获取，此处不重复列举。

| 工作场景 | 需要加载的知识文件 | 关键关注点 |
|---------|-------------------|-----------|
| **新增相机功能/会话模式/场景模式** | `architecture.md` + `coding-standards.md` + `glossary.md` | 分层架构、接口合同层、会话状态机、Feature 组件、NAPI 属性向量组合 |
| **修改 IPC 通信/服务端逻辑** | `architecture.md` + `coding-standards.md` + `technologies/binder-ipc.md` + `glossary.md` | services 层职责、Binder Proxy/Stub、IDL 代码生成、IPC Code 路由 |
| **修改分段式后处理** | `architecture.md` + `coding-standards.md` + `glossary.md` | DPS 独立服务进程、事件驱动调度、作业状态机、多用户隔离 |
| **修改媒体流/管道/电影文件处理** | `architecture.md` + `technologies/surface-bufferqueue.md` + `glossary.md` | 管道+过滤器架构、CFilterFactory、生产者-消费者管道、tunneledMode |
| **修改动态库适配层** | `architecture.md` + `coding-standards.md` + `glossary.md` | dynamic_libs 适配器模式、CameraDynamicLoader 延迟卸载、Proxy 代理模式 |
| **修改 NDK/NAPI/替代语言绑定** | `coding-standards.md` + `glossary.md` | opaque 指针、NAPI 绑定、thread_local 会话传递、属性向量组合、CJ FFI / Taihe ANI mixin |
| **修改网络相机引擎** | `architecture.md` + `glossary.md` | RTSP/HTTP/WebSocket 客户端、资源下载重试、优先级调度 |
| **修改 DFX（日志/事件/追踪/超时）** | `technologies/dfx-framework.md` + `coding-standards.md` | HiLog/HiSysEvent/HiTrace/XCollie、日志域、事件上报 |
| **修改 HDI 硬件交互** | `technologies/hdi-camera-host.md` + `glossary.md` | HDI V1_0~V1_7 版本兼容、CamRetCode 转换、StreamOperator |
| **修改服务注册/发现** | `technologies/system-ability.md` | SA 注册与发现、SA ID 3008、samgr 交互 |
| **排查编译错误** | 本文件（编译命令 + 构建产物） | 编译目标、依赖关系、命名空间 |
| **排查运行时错误** | `glossary.md`（→ `error-codes.md`）+ `technologies/dfx-framework.md` | 错误码定义与转换、超时约束、可靠性机制 |
| **排查 IPC 通信问题** | `technologies/binder-ipc.md` + `glossary.md` | Proxy/Stub 代码生成、IPC Code 路由 |
| **排查帧数据流转问题** | `technologies/surface-bufferqueue.md` + `glossary.md` | BufferQueue 生产者-消费者管道、tunneledMode |

### 3.5 平台技术索引

`technologies/` 目录下的文件不在 glossary 中索引，按以下规则按需加载：

| 文件 | 覆盖场景 | 触发关键词 |
|------|---------|-----------|
| `technologies/binder-ipc.md` | IPC 通信、Proxy/Stub、IDL 代码生成、跨进程回调 | Binder / IPC / Proxy / Stub / IDL / MessageParcel |
| `technologies/dfx-framework.md` | 日志、事件上报、性能追踪、超时检测 | HiLog / HiSysEvent / HiTrace / XCollie / DFX / LOG_DOMAIN |
| `technologies/hdi-camera-host.md` | 硬件驱动接口、版本兼容、StreamOperator | HDI / Camera Host / StreamOperator / V1_0~V1_7 / CamRetCode |
| `technologies/surface-bufferqueue.md` | 帧数据缓冲管道、共享内存、零拷贝 | Surface / BufferQueue / IBufferProducer / tunneledMode |
| `technologies/system-ability.md` | 系统服务注册、发现、生命周期 | SystemAbility / samgr / SA ID 3008 / SA Profile |


