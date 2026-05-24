const RANDOM_LEN = 40;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let wasm;

const elements = {
  runtimeStatus: document.querySelector("#runtime-status"),
  tabs: [...document.querySelectorAll(".tab")],
  encodePanel: document.querySelector("#encode-panel"),
  decodePanel: document.querySelector("#decode-panel"),
  scanPanel: document.querySelector("#scan-panel"),
  visibleText: document.querySelector("#visible-text"),
  hiddenText: document.querySelector("#hidden-text"),
  encodePassword: document.querySelector("#encode-password"),
  encodedOutput: document.querySelector("#encoded-output"),
  encodedInput: document.querySelector("#encoded-input"),
  decodePassword: document.querySelector("#decode-password"),
  decodedOutput: document.querySelector("#decoded-output"),
  scanInput: document.querySelector("#scan-input"),
  scanOutput: document.querySelector("#scan-output"),
  scanHex: document.querySelector("#scan-hex"),
  encodeButton: document.querySelector("#encode-button"),
  decodeButton: document.querySelector("#decode-button"),
  scanButton: document.querySelector("#scan-button"),
  copyEncoded: document.querySelector("#copy-encoded"),
  copyDecoded: document.querySelector("#copy-decoded"),
  copyScan: document.querySelector("#copy-scan"),
  encodeMessage: document.querySelector("#encode-message"),
  decodeMessage: document.querySelector("#decode-message"),
  scanMessage: document.querySelector("#scan-message"),
};

init();

async function init() {
  setBusy(true);

  try {
    wasm = await loadWasm();
    elements.runtimeStatus.textContent = "WASM ready";
    elements.runtimeStatus.className = "status ready";
  } catch (error) {
    elements.runtimeStatus.textContent = error.message;
    elements.runtimeStatus.className = "status error";
    return;
  } finally {
    setBusy(false);
  }

  bindUi();
}

async function loadWasm() {
  const imports = {};

  if (WebAssembly.instantiateStreaming) {
    try {
      const result = await WebAssembly.instantiateStreaming(
        fetch("./raphecrypt.wasm"),
        imports,
      );
      return result.instance.exports;
    } catch (_error) {
      // Some static servers do not send `application/wasm`.
    }
  }

  const response = await fetch("./raphecrypt.wasm");

  if (!response.ok) {
    throw new Error("WASM file not found");
  }

  const bytes = await response.arrayBuffer();
  const result = await WebAssembly.instantiate(bytes, imports);

  return result.instance.exports;
}

function bindUi() {
  elements.tabs.forEach((tab) => {
    tab.addEventListener("click", () => selectMode(tab.dataset.mode));
  });

  elements.encodeButton.addEventListener("click", encodeText);
  elements.decodeButton.addEventListener("click", decodeText);
  elements.scanButton.addEventListener("click", scanText);
  elements.copyEncoded.addEventListener("click", () =>
    copyText(elements.encodedOutput.value, elements.encodeMessage),
  );
  elements.copyDecoded.addEventListener("click", () =>
    copyText(elements.decodedOutput.value, elements.decodeMessage),
  );
  elements.copyScan.addEventListener("click", () =>
    copyText(elements.scanOutput.value, elements.scanMessage),
  );
}

function selectMode(mode) {
  elements.tabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.mode === mode);
  });

  elements.encodePanel.classList.toggle("active", mode === "encode");
  elements.decodePanel.classList.toggle("active", mode === "decode");
  elements.scanPanel.classList.toggle("active", mode === "scan");
}

function encodeText() {
  clearMessage(elements.encodeMessage);

  try {
    const password = elements.encodePassword.value;
    const random = password ? cryptoRandomBytes(RANDOM_LEN) : new Uint8Array();
    const output = callWasmString(
      wasm.raphecrypt_encode,
      elements.visibleText.value,
      elements.hiddenText.value,
      password,
      random,
    );

    elements.encodedOutput.value = output;
    elements.encodedInput.value = output;
    elements.scanInput.value = output;
    renderHex(elements.scanHex, output);
    showMessage(elements.encodeMessage, "Encoded", "ok");
  } catch (error) {
    showMessage(elements.encodeMessage, error.message, "error");
  }
}

function scanText() {
  clearMessage(elements.scanMessage);

  try {
    const output = callWasmString(wasm.raphecrypt_scan, elements.scanInput.value);

    elements.scanOutput.value = output;
    renderHex(elements.scanHex, elements.scanInput.value);
    showMessage(elements.scanMessage, "Scanned", "ok");
  } catch (error) {
    elements.scanOutput.value = "";
    showMessage(elements.scanMessage, error.message, "error");
  }
}

function renderHex(element, value) {
  element.replaceChildren(...formatHexNodes(value));
}

function formatHexNodes(value) {
  const bytes = encoder.encode(value);
  const hiddenByteIndexes = nonVisibleByteIndexes(value);
  const nodes = [];

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const address = offset.toString(16).padStart(8, "0");
    const hexNodes = [...chunk].flatMap((byte, index) => {
      const byteIndex = offset + index;
      const span = document.createElement("span");
      span.className = hiddenByteIndexes.has(byteIndex)
        ? "hex-byte hidden"
        : "hex-byte";
      span.textContent = byte.toString(16).padStart(2, "0");

      return index === chunk.length - 1 ? [span] : [span, " "];
    });
    const padding = " ".repeat(Math.max(0, 47 - (chunk.length * 3 - 1)));
    const ascii = [...chunk]
      .map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : "."))
      .join("");

    nodes.push(`${address}: `, ...hexNodes, `${padding}  ${ascii}`);

    if (offset + 16 < bytes.length) {
      nodes.push("\n");
    }
  }

  return nodes;
}

function nonVisibleByteIndexes(value) {
  const indexes = new Set();
  let byteIndex = 0;

  for (const character of value) {
    const bytes = encoder.encode(character);

    if (isNonVisibleCharacter(character)) {
      for (let index = 0; index < bytes.length; index += 1) {
        indexes.add(byteIndex + index);
      }
    }

    byteIndex += bytes.length;
  }

  return indexes;
}

function isNonVisibleCharacter(character) {
  if (character === "\n" || character === "\r" || character === "\t" || character === " ") {
    return false;
  }

  const codepoint = character.codePointAt(0);

  return (
    isUnicodeTagCharacter(codepoint) ||
    isKnownFormatCharacter(codepoint) ||
    isPrivateUseCharacter(codepoint) ||
    isControlCharacter(codepoint) ||
    isNonAsciiWhitespace(character)
  );
}

function isUnicodeTagCharacter(codepoint) {
  return codepoint === 0xe0001 || (codepoint >= 0xe0020 && codepoint <= 0xe007f);
}

function isKnownFormatCharacter(codepoint) {
  return (
    codepoint === 0x00ad ||
    codepoint === 0x034f ||
    codepoint === 0x061c ||
    codepoint === 0x070f ||
    codepoint === 0x180e ||
    (codepoint >= 0x200b && codepoint <= 0x200f) ||
    (codepoint >= 0x202a && codepoint <= 0x202e) ||
    (codepoint >= 0x2060 && codepoint <= 0x206f) ||
    codepoint === 0xfeff ||
    (codepoint >= 0xfff9 && codepoint <= 0xfffb) ||
    (codepoint >= 0x1bca0 && codepoint <= 0x1bca3) ||
    (codepoint >= 0x1d173 && codepoint <= 0x1d17a)
  );
}

function isPrivateUseCharacter(codepoint) {
  return (
    (codepoint >= 0xe000 && codepoint <= 0xf8ff) ||
    (codepoint >= 0xf0000 && codepoint <= 0xffffd) ||
    (codepoint >= 0x100000 && codepoint <= 0x10fffd)
  );
}

function isControlCharacter(codepoint) {
  return codepoint < 0x20 || (codepoint >= 0x7f && codepoint <= 0x9f);
}

function isNonAsciiWhitespace(character) {
  return /\s/u.test(character) && !["\n", "\r", "\t", " "].includes(character);
}

function decodeText() {
  clearMessage(elements.decodeMessage);

  try {
    const output = callWasmString(
      wasm.raphecrypt_decode,
      elements.encodedInput.value,
      elements.decodePassword.value,
    );

    elements.decodedOutput.value = output;
    showMessage(elements.decodeMessage, "Decoded", "ok");
  } catch (_error) {
    elements.decodedOutput.value = "";
    showMessage(elements.decodeMessage, "Decode failed", "error");
  }
}

function callWasmString(fn, ...values) {
  const allocations = values.map((value) =>
    value instanceof Uint8Array ? allocBytes(value) : allocText(value),
  );

  try {
    const args = allocations.flatMap((allocation) => [
      allocation.ptr,
      allocation.len,
    ]);
    const packed = fn(...args);

    if (packed === 0n) {
      throw new Error(takeLastError());
    }

    return takeResult(packed);
  } finally {
    allocations.forEach((allocation) => {
      if (allocation.ptr !== 0 && allocation.len > 0) {
        wasm.raphecrypt_dealloc(allocation.ptr, allocation.len);
      }
    });
  }
}

function allocText(value) {
  return allocBytes(encoder.encode(value));
}

function allocBytes(bytes) {
  if (bytes.length === 0) {
    return { ptr: 0, len: 0 };
  }

  const ptr = wasm.raphecrypt_alloc(bytes.length);
  new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);

  return { ptr, len: bytes.length };
}

function takeResult(packed) {
  const { ptr, len } = unpackPtrLen(packed);

  if (len === 0) {
    return "";
  }

  const bytes = new Uint8Array(wasm.memory.buffer, ptr, len);
  const value = decoder.decode(bytes);
  wasm.raphecrypt_free_result(ptr, len);

  return value;
}

function takeLastError() {
  const packed = wasm.raphecrypt_last_error();
  return takeResult(packed);
}

function unpackPtrLen(packed) {
  return {
    ptr: Number(packed >> 32n),
    len: Number(packed & 0xffff_ffffn),
  };
}

function cryptoRandomBytes(len) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function copyText(value, messageElement) {
  clearMessage(messageElement);

  try {
    await navigator.clipboard.writeText(value);
    showMessage(messageElement, "Copied", "ok");
  } catch (_error) {
    showMessage(messageElement, "Copy failed", "error");
  }
}

function clearMessage(element) {
  element.textContent = "";
  element.className = "message";
}

function showMessage(element, message, kind) {
  element.textContent = message;
  element.className = `message ${kind}`;
}

function setBusy(isBusy) {
  [
    elements.encodeButton,
    elements.decodeButton,
    elements.scanButton,
    elements.copyEncoded,
    elements.copyDecoded,
    elements.copyScan,
  ].forEach((button) => {
    button.disabled = isBusy;
  });
}
