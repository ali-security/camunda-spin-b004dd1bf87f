/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
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
package com.fasterxml.jackson.core.json.async;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonFactoryBuilder;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.async.ByteArrayFeeder;
import com.fasterxml.jackson.core.async.ByteBufferFeeder;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-18401 (jackson-core GHSA-72hv-8253-57qq / #1555 and
 * follow-up #1611 / GHSA-r7wm-3cxj-wff9): the non-blocking (async) JSON parser of the
 * shaded jackson-core must enforce {@code StreamReadConstraints.maxNumberLength} for
 * integer, fraction and exponent parts, both when the whole number is available and
 * when digit-only input is streamed across many chunks.
 */
public class AsyncNumberLengthLimitTest {

  private static final int MAX_NUM_LEN = 1000;

  private static final int TEST_NUMBER_LENGTH = StreamReadConstraints.DEFAULT_MAX_NUM_LEN * 2;

  // Chunk size exceeds maxNumberLength after the very first chunk.
  private static final int CHUNK_SIZE = 4 * 1024;

  // Hard cap on chunks fed: well past maxNumberLength but bounded so a regressed
  // build cannot exhaust memory.
  private static final int MAX_CHUNKS = 32;

  private static final int SMALL_CHUNK = 100;

  // Default factory: maxNumberLength == StreamReadConstraints.DEFAULT_MAX_NUM_LEN (1000)
  private final JsonFactory defaultFactory = new JsonFactory();

  private final JsonFactory strictFactory = new JsonFactoryBuilder()
      .streamReadConstraints(StreamReadConstraints.builder()
          .maxNumberLength(MAX_NUM_LEN)
          .build())
      .build();

  /*
   * Whole number available in a single feed (GHSA-72hv-8253-57qq, #1555)
   */

  @Test
  public void shouldRejectTooLongIntegerFedAtOnce() throws Exception {
    assertTooLongNumberRejected(utf8("{\"v\":" + digitString(TEST_NUMBER_LENGTH) + "}"),
        JsonToken.VALUE_NUMBER_INT);
  }

  @Test
  public void shouldRejectTooLongNegativeIntegerFedAtOnce() throws Exception {
    assertTooLongNumberRejected(utf8("{\"v\":-" + digitString(TEST_NUMBER_LENGTH) + "}"),
        JsonToken.VALUE_NUMBER_INT);
  }

  @Test
  public void shouldRejectTooLongDecimalFedAtOnce() throws Exception {
    assertTooLongNumberRejected(utf8("{\"v\":0." + digitString(TEST_NUMBER_LENGTH) + "}"),
        JsonToken.VALUE_NUMBER_FLOAT);
  }

  @Test
  public void shouldRejectTooLongDecimalWithExponentFedAtOnce() throws Exception {
    assertTooLongNumberRejected(utf8("{\"v\":1.1E" + digitString(TEST_NUMBER_LENGTH)),
        JsonToken.VALUE_NUMBER_FLOAT);
  }

  @Test
  public void shouldRejectTooLongIntegerInArray() throws Exception {
    assertTooLongNumberRejected(utf8("[" + digitString(TEST_NUMBER_LENGTH) + "]"),
        JsonToken.VALUE_NUMBER_INT);
  }

  @Test
  public void shouldRejectTooLongRootLevelIntegerFedInSmallChunks() throws Exception {
    byte[] payload = utf8(digitString(TEST_NUMBER_LENGTH) + " ");

    try (JsonParser p = defaultFactory.createNonBlockingByteArrayParser()) {
      ByteArrayFeeder feeder = (ByteArrayFeeder) p.getNonBlockingInputFeeder();
      try {
        for (int off = 0; off < payload.length; off += SMALL_CHUNK) {
          feeder.feedInput(payload, off, Math.min(off + SMALL_CHUNK, payload.length));
          JsonToken t;
          while ((t = p.nextToken()) != JsonToken.NOT_AVAILABLE) {
            if (t == JsonToken.VALUE_NUMBER_INT) {
              fail("Async parser accepted a " + p.getText().length() + "-digit root-level integer");
            }
          }
        }
        feeder.endOfInput();
        while (p.nextToken() != null) {
          if (p.currentToken() == JsonToken.VALUE_NUMBER_INT) {
            fail("Async parser accepted a " + p.getText().length() + "-digit root-level integer");
          }
        }
        fail("Async parser must reject a " + TEST_NUMBER_LENGTH + "-digit root-level integer");
      } catch (StreamConstraintsException e) {
        verifyNumberLengthMessage(e);
      }
    }
  }

  /*
   * Digit-only input streamed across chunks, no terminator, no endOfInput()
   * (#1611 / GHSA-r7wm-3cxj-wff9)
   */

  @Test
  public void shouldRejectIntegerStreamedInLargeChunks() throws Exception {
    assertStreamedDigitsRejectedPromptly(strictFactory.createNonBlockingByteArrayParser(),
        "{\"v\":", CHUNK_SIZE);
  }

  @Test
  public void shouldRejectFractionStreamedInLargeChunks() throws Exception {
    assertStreamedDigitsRejectedPromptly(strictFactory.createNonBlockingByteArrayParser(),
        "{\"v\":0.", CHUNK_SIZE);
  }

  @Test
  public void shouldRejectIntegerStreamedInLargeChunksWithByteBufferParser() throws Exception {
    assertStreamedDigitsRejectedPromptly(strictFactory.createNonBlockingByteBufferParser(),
        "{\"v\":", CHUNK_SIZE);
  }

  @Test
  public void shouldRejectIntegerStreamedInSmallChunksAtBoundary() throws Exception {
    // 1000 digits ok after chunk 10, 1100 > 1000 at chunk 11
    int expectedFailChunk = (MAX_NUM_LEN / SMALL_CHUNK) + 1;
    int chunksFed = streamDigitsUntilRejected(strictFactory.createNonBlockingByteArrayParser(),
        "{\"v\":", SMALL_CHUNK);

    assertTrue("Exception fired on a single chunk; cross-chunk accumulation not exercised",
        chunksFed > 1);
    assertTrue("StreamConstraintsException raised too late: after " + chunksFed + " chunks",
        chunksFed <= expectedFailChunk + 1);
  }

  @Test
  public void shouldRejectNegativeIntegerStreamedInSmallChunksAtBoundary() throws Exception {
    // sign is excluded from the validated length: same boundary as the positive case
    int expectedFailChunk = (MAX_NUM_LEN / SMALL_CHUNK) + 1;
    int chunksFed = streamDigitsUntilRejected(strictFactory.createNonBlockingByteArrayParser(),
        "{\"v\":-", SMALL_CHUNK);

    assertTrue("StreamConstraintsException raised too early (sign likely counted): after "
        + chunksFed + " chunks", chunksFed >= expectedFailChunk);
    assertTrue("StreamConstraintsException raised too late: after " + chunksFed + " chunks",
        chunksFed <= expectedFailChunk + 1);
  }

  @Test
  public void shouldRejectExponentStreamedInSmallChunksAtBoundary() throws Exception {
    // "1.1E" contributes 1 integer + 1 fraction digit: validated length after k chunks
    // is 2 + 100k, so 902 ok at chunk 9 and 1002 > 1000 at chunk 10
    int expectedFailChunk = ((MAX_NUM_LEN - 2) / SMALL_CHUNK) + 1;
    int chunksFed = streamDigitsUntilRejected(strictFactory.createNonBlockingByteArrayParser(),
        "{\"v\":1.1E", SMALL_CHUNK);

    assertTrue("Exception fired on a single chunk; cross-chunk accumulation not exercised",
        chunksFed > 1);
    assertTrue("StreamConstraintsException raised too late: after " + chunksFed + " chunks",
        chunksFed <= expectedFailChunk + 1);
  }

  @Test
  public void shouldParseIntegerJustUnderLimitStreamedInSmallChunks() throws Exception {
    String number = digitString(MAX_NUM_LEN - 1);

    try (JsonParser p = strictFactory.createNonBlockingByteArrayParser()) {
      ByteArrayFeeder feeder = (ByteArrayFeeder) p.getNonBlockingInputFeeder();
      feedAndDrain(p, utf8("{\"v\":"));

      byte[] digits = utf8(number);
      for (int off = 0; off < digits.length; off += SMALL_CHUNK) {
        feeder.feedInput(digits, off, Math.min(off + SMALL_CHUNK, digits.length));
        assertEquals(JsonToken.NOT_AVAILABLE, p.nextToken());
      }

      byte[] tail = utf8("}");
      feeder.feedInput(tail, 0, tail.length);
      feeder.endOfInput();

      assertEquals(JsonToken.VALUE_NUMBER_INT, p.nextToken());
      assertEquals(number, p.getText());
      assertEquals(JsonToken.END_OBJECT, p.nextToken());
    }
  }

  @Test
  public void shouldParseNumbersWithinLimit() throws Exception {
    String integer = digitString(MAX_NUM_LEN);
    String fraction = digitString(MAX_NUM_LEN - 2);
    byte[] payload = utf8("[" + integer + ",-" + integer + ",1." + fraction + ",1.1E"
        + digitString(MAX_NUM_LEN - 2) + "]");

    try (JsonParser p = defaultFactory.createNonBlockingByteArrayParser()) {
      ByteArrayFeeder feeder = (ByteArrayFeeder) p.getNonBlockingInputFeeder();
      feeder.feedInput(payload, 0, payload.length);
      feeder.endOfInput();

      assertEquals(JsonToken.START_ARRAY, p.nextToken());
      assertEquals(JsonToken.VALUE_NUMBER_INT, p.nextToken());
      assertEquals(integer, p.getText());
      assertEquals(JsonToken.VALUE_NUMBER_INT, p.nextToken());
      assertEquals("-" + integer, p.getText());
      assertEquals(JsonToken.VALUE_NUMBER_FLOAT, p.nextToken());
      assertEquals("1." + fraction, p.getText());
      assertEquals(JsonToken.VALUE_NUMBER_FLOAT, p.nextToken());
      assertEquals(JsonToken.END_ARRAY, p.nextToken());
    }
  }

  /*
   * Helper methods
   */

  private void assertTooLongNumberRejected(byte[] payload, JsonToken numberToken) throws Exception {
    try (JsonParser p = defaultFactory.createNonBlockingByteArrayParser()) {
      ByteArrayFeeder feeder = (ByteArrayFeeder) p.getNonBlockingInputFeeder();
      feeder.feedInput(payload, 0, payload.length);
      feeder.endOfInput();

      boolean foundNumber = false;
      try {
        while (p.nextToken() != null) {
          if (p.currentToken() == numberToken) {
            foundNumber = true;
            assertEquals("Async parser silently accepted all " + TEST_NUMBER_LENGTH + " digits",
                TEST_NUMBER_LENGTH, p.getText().length());
          }
        }
        fail("Async parser must reject a " + TEST_NUMBER_LENGTH + "-digit number (number found? "
            + foundNumber + ")");
      } catch (StreamConstraintsException e) {
        verifyNumberLengthMessage(e);
      }
    }
  }

  private void assertStreamedDigitsRejectedPromptly(JsonParser parser, String preamble, int chunkSize)
      throws Exception {
    int chunksFed = streamDigitsUntilRejected(parser, preamble, chunkSize);
    // chunkSize > maxNumberLength, so the first chunk past the limit must fail
    assertTrue("StreamConstraintsException raised too late: after " + chunksFed + " chunks of "
        + chunkSize + " digits (maxNumberLength=" + MAX_NUM_LEN + ")", chunksFed <= 2);
  }

  /**
   * Feeds the preamble, then digit-only chunks without a terminator or endOfInput(), and
   * returns the number of chunks fed when {@link StreamConstraintsException} was raised.
   */
  private int streamDigitsUntilRejected(JsonParser parser, String preamble, int chunkSize)
      throws Exception {
    try (JsonParser p = parser) {
      feedAndDrain(p, utf8(preamble));

      byte[] digits = utf8(digitString(chunkSize));
      int chunksFed = 0;
      try {
        for (int c = 0; c < MAX_CHUNKS; c++) {
          feed(p, digits);
          chunksFed++;
          JsonToken t = p.nextToken();
          if (t != JsonToken.NOT_AVAILABLE) {
            fail("Expected NOT_AVAILABLE while streaming digits, got: " + t);
          }
        }
        fail("Async parser accepted " + (chunkSize * MAX_CHUNKS) + " digits after '" + preamble
            + "' with maxNumberLength=" + MAX_NUM_LEN + "; expected StreamConstraintsException");
      } catch (StreamConstraintsException e) {
        verifyNumberLengthMessage(e);
      }
      return chunksFed;
    }
  }

  private static void feedAndDrain(JsonParser p, byte[] data) throws Exception {
    feed(p, data);
    JsonToken t;
    while ((t = p.nextToken()) != JsonToken.NOT_AVAILABLE) {
      if (t == null) {
        fail("Parser ended unexpectedly while draining preamble");
      }
    }
  }

  private static void feed(JsonParser p, byte[] data) throws Exception {
    Object feeder = p.getNonBlockingInputFeeder();
    if (feeder instanceof ByteBufferFeeder) {
      ((ByteBufferFeeder) feeder).feedInput(ByteBuffer.wrap(data));
    } else {
      ((ByteArrayFeeder) feeder).feedInput(data, 0, data.length);
    }
  }

  private static String digitString(int count) {
    StringBuilder sb = new StringBuilder(count);
    for (int i = 0; i < count; i++) {
      sb.append((char) ('1' + (i % 9)));
    }
    return sb.toString();
  }

  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static void verifyNumberLengthMessage(StreamConstraintsException e) {
    String msg = String.valueOf(e.getMessage());
    assertTrue("Unexpected message: " + msg, msg.contains("Number length"));
    assertTrue("Unexpected message: " + msg, msg.contains("exceeds the maximum length"));
  }
}
