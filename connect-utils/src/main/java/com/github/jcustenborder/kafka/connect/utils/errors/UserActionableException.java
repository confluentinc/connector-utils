/**
 * Copyright © 2016 Jeremy Custenborder (jcustenborder@gmail.com)
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
package com.github.jcustenborder.kafka.connect.utils.errors;

import org.apache.kafka.connect.errors.ConnectException;

/**
 * Indicates a user-actionable error in connector configuration or runtime
 * environment.
 *
 * <p>The message of this exception is expected to be directly user-facing:
 * sanitized (no secrets), non-sensitive, and phrased as an actionable
 * instruction for the operator.</p>
 *
 * <p>Runtimes or management planes (for example, Confluent Cloud) may
 * treat this exception type specially when deriving connector status or
 * surfacing errors to end users.</p>
 */
public class UserActionableException extends ConnectException {

  public UserActionableException(String message) {
    super(message);
  }

  public UserActionableException(String message, Throwable cause) {
    super(message, cause);
  }

  public UserActionableException(Throwable cause) {
    super(cause);
  }
}
