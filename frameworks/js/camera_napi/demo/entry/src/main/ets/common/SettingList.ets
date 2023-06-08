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

import { SettingRightLayout } from '../common/SettingRightLayout';
import Logger from '../model/Logger';

const TAG = 'SettingList';

@CustomDialog
export default struct SettingList {
  private controller: CustomDialogController;
  @Link leftSliderIndex: number;
  @State isIndex: number = 0;

  aboutToAppear(): void {
    this.onSettingMessageFn();
  }

  onSettingMessageFn(): void {
    Logger.info(TAG, `onSettingMessageFn settingMessageNum: ${this.leftSliderIndex}`);
    switch (this.leftSliderIndex) {
      case 2:
        this.isIndex = globalThis.settingDataObj.videoStabilizationMode;
        break;
      case 3:
        this.isIndex = globalThis.settingDataObj.exposureMode;
        break;
      case 4:
        this.isIndex = globalThis.settingDataObj.focusMode;
        break;
      case 5:
        this.isIndex = globalThis.settingDataObj.photoQuality;
        break;
      case 7:
        this.isIndex = globalThis.settingDataObj.photoFormat;
        break;
      case 8:
        this.isIndex = globalThis.settingDataObj.photoOrientation;
        break;
      case 9:
        this.isIndex = globalThis.settingDataObj.photoResolution;
        break;
      case 10:
        this.isIndex = globalThis.settingDataObj.videoResolution;
        break;
      case 11:
        this.isIndex = globalThis.settingDataObj.videoFrame;
        break;
    }
  }

  build() {
    Column() {
      SettingRightLayout({
        settingMessageNum: $leftSliderIndex,
        controller: this.controller,
        isIndex: $isIndex
      })
    }
    .size({ width: '100%', height: '100%' })
    .backgroundColor('#F1F3F5')
  }
}