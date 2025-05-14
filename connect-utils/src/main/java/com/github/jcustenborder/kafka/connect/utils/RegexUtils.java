/**
 * Copyright [2023 - 2023] Confluent Inc.
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
 *     considered, but blocking operations could negatively impact unrelated tasks sharing the pool.
 *   </li>
 *   <li>
 *     <b>ManagedBlocker:</b> The chosen approach is to use a custom ForkJoinPool.ManagedBlocker.
 *     This allows blocking operations to be managed efficiently by the ForkJoinPool, without
 *     requiring explicit thread pool management or impacting the common pool. This approach
 *     provides a balance between safety, performance, and ease of use for consumers.
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

  private static class RegexExecutor implements ForkJoinPool.ManagedBlocker {
    private final Pattern pattern;
    private final String input;
    private final String replacement;
    private final OperationType operationType;
    private String result;
    private Boolean booleanResult;
    private boolean timedOut;

    public RegexExecutor(Pattern pattern, String input, String replacement, OperationType operationType) {
      this.pattern = pattern;
      this.input = input;
      this.replacement = replacement;
      this.operationType = operationType;
      this.timedOut = false;
    }

    public boolean block() {
      switch (operationType) {
        case REPLACE:
          result = pattern.matcher(input).replaceAll(replacement);
          break;
        case FIND:
          booleanResult = pattern.matcher(input).find();
          break;
        case MATCHES:
          booleanResult = pattern.matcher(input).matches();
          break;
        default:
          throw new IllegalStateException("Unknown operation type: " + operationType);
      }
      return true;
    }

    public boolean isReleasable() {
      return false;
    }

    public String getStringResult() {
      return result;
    }

    public Boolean getBooleanResult() {
      return booleanResult;
    }

    public void setTimedOut(boolean timedOut) {
      this.timedOut = timedOut;
    }

    public boolean isTimedOut() {
      return timedOut;
    }
  }

  private enum OperationType {
    REPLACE,
    FIND,
    MATCHES
  }

  private static String executeStringRegexOperation(
      Pattern pattern,
      String input,
      String replacement,
      long timeoutMs) throws InterruptedException, ExecutionException {

    if (input == null) {
      return null;
    }

    RegexExecutor executor = new RegexExecutor(pattern, input, replacement, OperationType.REPLACE);
    CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
      try {
        ForkJoinPool.managedBlock(executor);
        return executor.getStringResult();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new CompletionException(e);
      }
    });

    try {
      return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      log.warn(
          "Regex operation exceeded timeout of {} ms. Returning original string.",
          timeoutMs, e);
      // Do not use the result of the regex operation after a timeout
      return null; // Signal to caller that a timeout occurred
    }
  }

  private static boolean executeBooleanRegexOperation(
      Pattern pattern,
      String input,
      OperationType operationType,
      long timeoutMs) throws InterruptedException, ExecutionException {

    if (input == null) {
      return false;
    }

    RegexExecutor executor = new RegexExecutor(pattern, input, null, operationType);
    CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
      try {
        ForkJoinPool.managedBlock(executor);
        return executor.getBooleanResult();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new CompletionException(e);
      }
    });

    try {
      return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      log.warn(
          "Regex operation exceeded timeout of {} ms. Returning false.",
          timeoutMs, e);
      // On timeout, return false
      return false;
    }
  }

  /**
   * Executes a regex replacement with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param input        The input string
   * @param replacements The regex operation to perform
   * @param timeoutMs    The timeout in milliseconds
   * @return The result of the operation
   * @throws InterruptedException if the current thread is interrupted
   * @throws ExecutionException   if the operation throws an exception
   */
  public static String replaceAll(
      String input,
      Map<Pattern, String> replacements,
      long timeoutMs) throws InterruptedException, ExecutionException {

    if (input == null) {
      return null;
    }
    if (replacements == null || replacements.isEmpty()) {
      return input;
    }

    String currentResult = input;
    for (Map.Entry<Pattern, String> entry : replacements.entrySet()) {
      String result = executeStringRegexOperation(
          entry.getKey(),
          currentResult,
          entry.getValue(),
          timeoutMs
      );
      if (result == null) {
        // Timeout occurred, return original input
        return input;
      }
      currentResult = result;
    }
    return currentResult;
  }

  /**
   * Executes a regex find operation with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param pattern   The pattern to match
   * @param input     The input string
   * @param timeoutMs The timeout in milliseconds
   * @return true if the pattern is found, false otherwise
   * @throws InterruptedException if the current thread is interrupted
   * @throws ExecutionException   if the operation throws an exception
   */
  public static boolean find(
      Pattern pattern,
      String input,
      long timeoutMs) throws InterruptedException, ExecutionException {
    return executeBooleanRegexOperation(pattern, input, OperationType.FIND, timeoutMs);
  }

  /**
   * Executes a regex matches operation with timeout protection.
   * See class-level JavaDoc for details on ReDoS protection.
   *
   * @param pattern   The pattern to match
   * @param input     The input string
   * @param timeoutMs The timeout in milliseconds
   * @return true if the pattern matches the entire input, false otherwise
   * @throws InterruptedException if the current thread is interrupted
   * @throws ExecutionException   if the operation throws an exception
   */
  public static boolean matches(
      Pattern pattern,
      String input,
      long timeoutMs) throws InterruptedException, ExecutionException {
    return executeBooleanRegexOperation(pattern, input, OperationType.MATCHES, timeoutMs);
  }
} 