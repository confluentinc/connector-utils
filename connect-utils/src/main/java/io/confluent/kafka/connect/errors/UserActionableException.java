/**
 * Copyright the project authors.
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
package io.confluent.kafka.connect.errors;

import org.apache.kafka.connect.errors.ConnectException;

/**
 * Exception for user-actionable connector errors. The message should be
 * user-facing, sanitized, and actionable; runtimes may treat this type
 * specially when surfacing errors to users.
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
