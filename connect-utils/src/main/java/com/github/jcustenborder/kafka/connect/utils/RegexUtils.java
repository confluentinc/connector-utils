/**
 * Copyright [2025 - 2025] Confluent Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.jcustenborder.kafka.connect.utils;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for performing regex operations with timeout protection against ReDoS attacks.
 * This class provides methods for regex replacement, finding, and matching operations.
 *
 * <p><b>Design Decision:</b></p>
 * <p>
 * Timeout enforcement is implemented using a custom {@link CharSequence} wrapper that checks
 * a deadline on every {@code charAt()} call. Since {@code java.util.regex} accesses every
 * character through this method, this provides fine-grained timeout detection that runs on the
 * calling thread — no thread pool is required. The deadline check is amortized to every 64th
 * {@code charAt()} call using a bitmask to minimize overhead.
 * </p>
 * <p>
 * The deadline uses {@code System.nanoTime()} (monotonic wall-clock time). This is safe because
 * the timeout starts immediately before regex execution on the calling thread — there is no
 * thread pool or task queuing where wall-clock time could advance before execution begins.
 * </p>
 * <p>
 * <b>Why not {@link java.lang.management.ThreadMXBean#getCurrentThreadCpuTime()}?</b>
 * Thread CPU time was considered as it only counts actual CPU execution (immune to CFS throttling
 * pauses). However, {@code getCurrentThreadCpuTime()} is not portable across JVM implementations:
 * it is an optional operation that may return {@code -1} when unsupported, and implementations
 * like OpenJ9 (IBM Semeru) do not support it. Additionally, even on HotSpot where it is supported,
 * it incurs ~100–500ns per call (vs ~20–30ns for {@code System.nanoTime()}) due to underlying
 * OS syscalls ({@code clock_gettime(CLOCK_THREAD_CPUTIME_ID)} on Linux,
 * {@code thread_info()} on macOS). Since the timeout runs inline on the calling thread with no
 * queuing delay, wall-clock time is sufficient — for ReDoS patterns the thread burns CPU
 * continuously so both clocks advance at the same rate, and for non-pathological patterns
 * execution completes in microseconds well within the timeout margin.
 * </p>
 *
 * <p>See also:
 * <a href="https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS">
 * OWASP ReDoS</a></p>
 */
public final class RegexUtils {
  private static final Logger log = LoggerFactory.getLogger(RegexUtils.class);

  private RegexUtils() {
    // Prevent instantiation
  }

  /**
   * A {@link CharSequence} wrapper that enforces a wall-clock deadline on regex operations.
   * Throws a {@link RuntimeException} wrapping a {@link TimeoutException} when the
   * deadline is exceeded, interrupting the regex engine mid-execution.
   */
  private static class TimeoutCharSequence implements CharSequence {
    private static final int CHECK_INTERVAL = 64;
    private final CharSequence inner;
    private final long deadlineNanos;
    private int accessCount;

    TimeoutCharSequence(CharSequence inner, long timeoutMs) {
      if (timeoutMs < 0) {
        throw new IllegalArgumentException("timeoutMs must be non-negative, got: " + timeoutMs);
      }
      this.inner = inner;
      this.deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
    }

    @Override
    public char charAt(int index) {
      if ((++accessCount & (CHECK_INTERVAL - 1)) == 0
          && System.nanoTime() > deadlineNanos) {
        throw new RuntimeException(
            new TimeoutException("Regex operation timed out"));
      }
      return inner.charAt(index);
    }

    @Override
    public int length() {
      return inner.length();
    }

    @Override
    public CharSequence subSequence(int start, int end) {
      long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime());
      return new TimeoutCharSequence(inner.subSequence(start, end), Math.max(remainingMs, 0));
    }

    @Override
    public String toString() {
      return inner.toString();
    }
  }

  private static <T> T executeWithTimeout(
      String input,
      T nullDefault,
      long timeoutMs,
      Function<CharSequence, T> operation) throws TimeoutException {
    if (input == null) {
      return nullDefault;
    }
    CharSequence guarded = new TimeoutCharSequence(input, timeoutMs);
    try {
      return operation.apply(guarded);
    } catch (RuntimeException e) {
      if (e.getCause() instanceof TimeoutException) {
        log.warn("Regex operation timed out after {}ms on input of length {}",
            timeoutMs, input.length());
        throw (TimeoutException) e.getCause();
      }
      throw e;
    }
  }

  /**
   * Executes a {@link Pattern#matcher(CharSequence) matcher()}.{@link java.util.regex.Matcher#replaceAll(String) replaceAll(String)} operation with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param input        The input string
   * @param replacements The regex operation to perform
   * @param timeoutMs    The timeout in milliseconds
   * @return The result of the operation
   * @throws TimeoutException     if the operation exceeds the specified timeout
   */
  public static String replaceAll(
      String input,
      Map<Pattern, String> replacements,
      long timeoutMs) throws TimeoutException {

    if (input == null) {
      return null;
    }
    if (replacements == null || replacements.isEmpty()) {
      return input;
    }

    String currentResult = input;
    for (Map.Entry<Pattern, String> entry : replacements.entrySet()) {
      currentResult = executeWithTimeout(currentResult, null, timeoutMs,
          guarded -> entry.getKey().matcher(guarded).replaceAll(entry.getValue()));
    }
    return currentResult;
  }

  /**
   * Executes a {@link Pattern#matcher(CharSequence) matcher()}.{@link java.util.regex.Matcher#find() find()} operation with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param pattern   The pattern to match
   * @param input     The input string
   * @param timeoutMs The timeout in milliseconds
   * @return true if the pattern is found, false otherwise
   * @throws TimeoutException     if the operation exceeds the specified timeout
   */
  public static boolean find(
      Pattern pattern,
      String input,
      long timeoutMs) throws TimeoutException {
    return executeWithTimeout(input, false, timeoutMs,
        guarded -> pattern.matcher(guarded).find());
  }

  /**
   * Executes a {@link Pattern#matcher(CharSequence) matcher()}.{@link java.util.regex.Matcher#matches() matches()} operation with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param pattern   The pattern to match
   * @param input     The input string
   * @param timeoutMs The timeout in milliseconds
   * @return true if the pattern matches the entire input, false otherwise
   * @throws TimeoutException     if the operation exceeds the specified timeout
   */
  public static boolean matches(
      Pattern pattern,
      String input,
      long timeoutMs) throws TimeoutException {
    return executeWithTimeout(input, false, timeoutMs,
        guarded -> pattern.matcher(guarded).matches());
  }

}
