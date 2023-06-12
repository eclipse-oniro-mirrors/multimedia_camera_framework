import prompt from '@ohos.prompt';
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import CameraService from '../model/CameraService';
import Logger from '../model/Logger';

const TAG: string = "SettingItem";

@Component
export struct SettingItem {
  private itemData: string; // 所选模式的名称
  @Prop settingMessageNum: number; // 传进来的点击设置
  private index: number; // 所选模式的索引值
  @Link @Watch('onChangeFn') isIndex: number; // 默认图标选在第几个
  @State isBol: boolean = false; // 隐藏显示图标

  /**
   * 对应点击模式设置下所选的设置参数
   */
  selectMode(): void {
    Logger.info(TAG, `selectMode settingMessageNum: ${this.settingMessageNum}`);
    switch (this.settingMessageNum) {
      case 2:
        globalThis.settingDataObj.videoStabilizationMode = this.index;
        CameraService.isVideoStabilizationModeSupportedFn(globalThis.settingDataObj.videoStabilizationMode);
        break;
      case 3:
        globalThis.settingDataObj.exposureMode = this.index;
        CameraService.isExposureModeSupportedFn(globalThis.settingDataObj.exposureMode);
        break;
      case 4:
        globalThis.settingDataObj.focusMode = this.index;
        CameraService.isFocusMode(globalThis.settingDataObj.focusMode);
        break;
      case 5:
        globalThis.settingDataObj.photoQuality = this.index;
        break;
      case 7:
        globalThis.settingDataObj.photoFormat = this.index;
        break;
      case 8:
        globalThis.settingDataObj.photoOrientation = this.index;
        break;
      case 9:
      // 照片分辨率
        globalThis.settingDataObj.photoResolution = this.index;
        let ind = this.itemData.indexOf('*');
        globalThis.photoResolutionWidth = Number(this.itemData.substring(0, ind));
        globalThis.photoResolutionHeight = Number(this.itemData.substring(ind + 1));
        AppStorage.Set<number>('defaultAspectRatio', globalThis.photoResolutionWidth/globalThis.photoResolutionHeight);
        break;
      case 10:
      // 视频分辨率
        globalThis.settingDataObj.videoResolution = this.index;
        let index = this.itemData.indexOf('*');
        globalThis.videoResolutionWidth = Number(this.itemData.substring(0, index));
        globalThis.videoResolutionHeight = Number(this.itemData.substring(index + 1));
        break;
      case 11:
        let isSupported = CameraService.isVideoFrameSupportedFn(Number(this.itemData));
        if (isSupported) {
          globalThis.settingDataObj.videoFrame = this.index;
          globalThis.videoFrame = this.itemData;
        }
        prompt.showToast({
          message: isSupported ? '支持此模式' : '不支持此模式',
          duration: 2000,
          bottom: '50%'
        });
        break;
    }
  }

  async resetSession(): Promise<void> {
    await CameraService.releaseCamera().then((): void => {
      Logger.debug(TAG, 'releaseCamera success');
    });
    await CameraService.initCamera(globalThis.surfaceId, globalThis.cameraDeviceIndex).then((): void => {
      Logger.debug(TAG, 'initCamera success');
    });
  }

  onChangeFn(): void {
    if (this.index === this.isIndex) {
      this.isBol = true;
    } else {
      this.isBol = false;
    }
  }

  aboutToAppear(): void {
    this.onChangeFn();
  }

  build() {
    Column() {
      Row() {
        Text(this.itemData)
          .fontColor('#182431')
          .fontSize(16)
          .fontWeight(600)
          .textAlign(TextAlign.Start)
          .width('90%')
        if (this.isBol) {
          Image($r('app.media.ic_camera_set_Checked'))
            .width(24)
            .height(24)
        } else {
          Image('')
            .width(24)
            .height(24)
            .backgroundColor(Color.White)
        }
      }
      .justifyContent(FlexAlign.SpaceBetween)
      .height(65)
      .onClick(async () => {
        if (this.isIndex === this.index) {
          return;
        }
        this.isIndex = this.index;
        this.selectMode();
        await this.resetSession();
      })

      Divider()
        .width('100%')
        .margin({ left: 10 })
    }

  }
}