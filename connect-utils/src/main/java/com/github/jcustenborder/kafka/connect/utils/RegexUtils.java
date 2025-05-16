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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import java.util.function.Supplier;

/**
 * Utility class for performing regex operations with timeout protection against ReDoS attacks.
 * This class provides methods for regex replacement, finding, and matching operations.
 *
 * <p><b>Design Decision:</b></p>
 * <ul>
 *   <li>
 *     <b>Custom ExecutorService:</b> Considered using a dedicated ExecutorService to manage
 *     threads for regex operations. However, this would require explicit lifecycle management
 *     (shutdown, resource cleanup) and would complicate usage for consumers of this utility class.
 *   </li>
 *   <li>
 *     <b>Common Thread Pool:</b> Using the common thread pool (e.g., via CompletableFuture) was
 *     considered, but multiple blocking operations might exhaust the common ForkJoinPool for other users.
 *   </li>
 *   <li>
 *     <b>ManagedBlocker:</b> The chosen approach is to use a custom ForkJoinPool.ManagedBlocker.
 *     This allows for dispatching blocking operations without exhausting the common ForkJoinPool,
 *     while avoiding the complexity of explicit thread pool management. This approach provides
 *     a balance between safety, performance, and ease of use for consumers.
 *   </li>
 * </ul>
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

  private static class RegexExecutor<T> implements ForkJoinPool.ManagedBlocker {
    private final Supplier<T> operation;
    private T result;

    public RegexExecutor(Supplier<T> operation) {
      this.operation = operation;
    }

    public boolean block() {
      result = operation.get();
      return true;
    }

    public boolean isReleasable() {
      return false;
    }

    public T getResult() {
      return result;
    }
  }

  private static <T> T executeOperation(
      Pattern pattern,
      String input,
      String replacement,
      Supplier<T> operation,
      long timeoutMs) throws InterruptedException, ExecutionException, TimeoutException {

    if (input == null) {
      return null;
    }

    RegexExecutor<T> executor = new RegexExecutor<>(operation);
    CompletableFuture<T> future = CompletableFuture.supplyAsync(() -> {
      try {
        ForkJoinPool.managedBlock(executor);
        return executor.getResult();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new CompletionException(e);
      }
    });

    try {
      return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      log.error(
          "Regex operation exceeded timeout of {} ms.",
          timeoutMs, e);
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
   * @throws InterruptedException if the current thread is interrupted
   * @throws ExecutionException   if the operation throws an exception
   * @throws TimeoutException     if the operation exceeds the specified timeout
   */
  public static String replaceAll(
      String input,
      Map<Pattern, String> replacements,
      long timeoutMs) throws InterruptedException, ExecutionException, TimeoutException {

    if (input == null) {
      return null;
    }
    if (replacements == null || replacements.isEmpty()) {
      return input;
    }

    String currentResult = input;
    for (Map.Entry<Pattern, String> entry : replacements.entrySet()) {
      final String currentInput = currentResult;
      currentResult = executeOperation(
          entry.getKey(),
          currentInput,
          entry.getValue(),
          () -> entry.getKey().matcher(currentInput).replaceAll(entry.getValue()),
          timeoutMs
      );
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
   * @throws InterruptedException if the current thread is interrupted
   * @throws ExecutionException   if the operation throws an exception
   * @throws TimeoutException     if the operation exceeds the specified timeout
   */
  public static boolean find(
      Pattern pattern,
      String input,
      long timeoutMs) throws InterruptedException, ExecutionException, TimeoutException {
    if (input == null) {
      return false;
    }
    return executeOperation(
        pattern,
        input,
        null,
        () -> pattern.matcher(input).find(),
        timeoutMs
    );
  }

  /**
   * Executes a {@link Pattern#matcher(CharSequence) matcher()}.{@link java.util.regex.Matcher#matches() matches()} operation with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param pattern   The pattern to match
   * @param input     The input string
   * @param timeoutMs The timeout in milliseconds
   * @return true if the pattern matches the entire input, false otherwise
   * @throws InterruptedException if the current thread is interrupted
   * @throws ExecutionException   if the operation throws an exception
   * @throws TimeoutException     if the operation exceeds the specified timeout
   */
  public static boolean matches(
      Pattern pattern,
      String input,
      long timeoutMs) throws InterruptedException, ExecutionException, TimeoutException {
    if (input == null) {
      return false;
    }
    return executeOperation(
        pattern,
        input,
        null,
        () -> pattern.matcher(input).matches(),
        timeoutMs
    );
  }
} 