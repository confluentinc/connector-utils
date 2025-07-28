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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
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
 *     <b>Dedicated ExecutorService:</b> All regex work is executed on a private, cached thread
 *     pool whose threads are marked <i>daemon</i>.  A hung regex can only consume a thread from
 *     this pool and will never starve the JVM&rsquo;s shared thread pools.
 *   </li>
 *   <li>
 *     <b>ManagedBlocker:</b> Each operation is wrapped in a custom
 *     {@link java.util.concurrent.ForkJoinPool.ManagedBlocker} so the pool can compensate for the
 *     blocking call without exhausting its parallelism.
 *   </li>
 *   <li>
 *     <b>Timeout &amp; Cleanup:</b> Callers supply a timeout.  On expiry the
 *     {@link CompletableFuture} is cancelled, ensuring the caller never hangs while any leaked
 *     thread remains confined to the private pool.
 *   </li>
 * </ul>
 *
 * <p>See also:
 * <a href="https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS">
 * OWASP ReDoS</a></p>
 */
public final class RegexUtils {
  private RegexUtils() {
    // Prevent instantiation
  }

  // Dedicated daemon-thread pool to isolate regex execution from the common ForkJoinPool.
  private static final ExecutorService REGEX_EXECUTOR_SERVICE = Executors.newCachedThreadPool(new ThreadFactory() {
    private final AtomicInteger idx = new AtomicInteger();

    @Override
    public Thread newThread(Runnable r) {
      Thread t = new Thread(r, "regex-util-" + idx.incrementAndGet());
      t.setDaemon(true); // ensure stuck threads don't block JVM shutdown
      return t;
    }
  });

  private static class RegexExecutor<T> implements ForkJoinPool.ManagedBlocker {
    private final Supplier<T> operation;
    private final AtomicBoolean done = new AtomicBoolean();
    private T result;

    private RegexExecutor(Supplier<T> operation) {
      this.operation = operation;
    }

    public boolean block() {
      if (done.compareAndSet(false, true)) {
        result = operation.get();
      }
      return true;
    }

    public boolean isReleasable() {
      return done.get();
    }

    public T getResult() {
      return result;
    }
  }

  private static <T> T executeOperation(
      Supplier<T> operation,
      long timeoutMs) throws InterruptedException, ExecutionException, TimeoutException {

    RegexExecutor<T> executor = new RegexExecutor<>(operation);
    CompletableFuture<T> future = CompletableFuture.supplyAsync(() -> {
      try {
        ForkJoinPool.managedBlock(executor);
        return executor.getResult();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new CompletionException(e);
      }
    }, REGEX_EXECUTOR_SERVICE);

    try {
      return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      // Attempt to cancel; regex operations aren't interruptible but avoids leaking the Future
      future.cancel(true);
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
    if (pattern == null) {
      throw new IllegalArgumentException("pattern cannot be null");
    }
    if (input == null) {
      return false;
    }
    return executeOperation(
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
    if (pattern == null) {
      throw new IllegalArgumentException("pattern cannot be null");
    }
    if (input == null) {
      return false;
    }
    return executeOperation(
        () -> pattern.matcher(input).matches(),
        timeoutMs
    );
  }
}
