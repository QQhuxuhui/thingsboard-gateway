/**
 * Copyright © 2023 The Thingsboard Authors
 *
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
package org.thingsboard.gateway.service.data;

import lombok.Builder;
import lombok.Data;

/**
 * Created by ashvayka on 02.03.17.
 */
@Data
@Builder
public class AttributeRequest {

    private final int requestId;
    private final String deviceName;
    private final String attributeKey;

    private final boolean clientScope;
    private final String topicExpression;
    private final String valueExpression;
}
